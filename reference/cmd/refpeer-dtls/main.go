// Command refpeer-dtls is a DTLS 1.2 peer backed by pion/dtls.
//
// The PHP DTLS stack is hand-written on phpseclib rather than bound to OpenSSL, so the only
// way to know its records are the ones a real peer expects is to hand them to one. This peer
// completes a handshake in either role, reports what it negotiated, and echoes application
// data back so the PHP side can check the protected path too.
//
// Progress is reported as JSON lines on stdout so the PHP side can wait for a specific event
// rather than sleeping:
//
//	{"event":"listening","port":45821,"fingerprint":"AB:CD:..."}
//	{"event":"connected","srtpProfile":"SRTP_AES128_CM_HMAC_SHA1_80","keyingMaterial":"<hex>"}
//	{"event":"echo","bytes":5}
//	{"event":"closed"}
//	{"event":"error","error":"..."}
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

// event is one line of the peer's progress report.
type event struct {
	Event          string `json:"event"`
	Port           int    `json:"port,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	SRTPProfile    string `json:"srtpProfile,omitempty"`
	KeyingMaterial string `json:"keyingMaterial,omitempty"`
	Bytes          int    `json:"bytes,omitempty"`
	Error          string `json:"error,omitempty"`
}

func emit(e event) {
	encoded, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "refpeer-dtls: cannot encode event: %v\n", err)
		return
	}
	fmt.Println(string(encoded))
	// The PHP side blocks on these lines, so nothing may sit in a buffer.
	os.Stdout.Sync()
}

func fail(err error) {
	emit(event{Event: "error", Error: err.Error()})
	os.Exit(1)
}

// srtpProfiles maps the profile names used in SDP to pion's constants, so a test can ask for
// exactly the profile it wants to check rather than whatever the default happens to be.
var srtpProfiles = map[string]dtls.SRTPProtectionProfile{
	"SRTP_AES128_CM_HMAC_SHA1_80": dtls.SRTP_AES128_CM_HMAC_SHA1_80,
	"SRTP_AES128_CM_HMAC_SHA1_32": dtls.SRTP_AES128_CM_HMAC_SHA1_32,
	"SRTP_AEAD_AES_128_GCM":       dtls.SRTP_AEAD_AES_128_GCM,
	"SRTP_AEAD_AES_256_GCM":       dtls.SRTP_AEAD_AES_256_GCM,
}

var profileNames = map[dtls.SRTPProtectionProfile]string{}

func init() {
	for name, profile := range srtpProfiles {
		profileNames[profile] = name
	}
}

// certificateFingerprint renders the SHA-256 fingerprint the way SDP carries it, which is
// what the PHP side compares against its a=fingerprint line.
func certificateFingerprint(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])

	parts := make([]string, 0, len(sum))
	for _, b := range sum {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}

	return strings.Join(parts, ":")
}

func buildConfig(profiles string) (*dtls.Config, tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	cert, err := selfsign.SelfSign(key)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	cfg := &dtls.Config{
		Certificates: []tls.Certificate{cert},
		// WebRTC authenticates the peer by the fingerprint carried in SDP, not by a chain,
		// so a self-signed certificate on either side is expected rather than a failure.
		InsecureSkipVerify: true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	if profiles != "" {
		for _, name := range strings.Split(profiles, ",") {
			profile, ok := srtpProfiles[strings.TrimSpace(name)]
			if !ok {
				return nil, tls.Certificate{}, fmt.Errorf("unknown SRTP profile %q", name)
			}
			cfg.SRTPProtectionProfiles = append(cfg.SRTPProtectionProfiles, profile)
		}
	}

	return cfg, cert, nil
}

// report announces what the handshake settled on, including the exported keying material
// that SRTP is keyed from: agreeing on a profile but deriving different keys is a failure
// mode worth catching separately.
func report(conn *dtls.Conn) {
	e := event{Event: "connected"}

	if profile, ok := conn.SelectedSRTPProtectionProfile(); ok {
		e.SRTPProfile = profileNames[profile]

		// RFC 5764 section 4.2: SRTP keying material is 2*(key + salt) bytes, and the
		// longest profile here needs 2*(32+12).
		if state, ok := conn.ConnectionState(); ok {
			if material, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, 88); err == nil {
				e.KeyingMaterial = hex.EncodeToString(material)
			}
		}
	}

	emit(e)
}

// echo mirrors application data back until the peer goes away, which lets the PHP side
// verify that records it protects are decryptable and vice versa.
func echo(conn *dtls.Conn) {
	buf := make([]byte, 8192)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			emit(event{Event: "closed"})
			return
		}

		if _, err := conn.Write(buf[:n]); err != nil {
			emit(event{Event: "error", Error: err.Error()})
			return
		}
		emit(event{Event: "echo", Bytes: n})
	}
}

func runServer(cfg *dtls.Config, cert tls.Certificate, timeout time.Duration) {
	listener, err := dtls.Listen("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}, cfg)
	if err != nil {
		fail(err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.UDPAddr)
	emit(event{
		Event:       "listening",
		Port:        addr.Port,
		Fingerprint: certificateFingerprint(cert),
	})

	conn, err := listener.Accept()
	if err != nil {
		fail(err)
	}
	defer conn.Close()

	dtlsConn := conn.(*dtls.Conn)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := dtlsConn.HandshakeContext(ctx); err != nil {
		fail(err)
	}

	report(dtlsConn)
	echo(dtlsConn)
}

func runClient(cfg *dtls.Config, cert tls.Certificate, addr string, timeout time.Duration) {
	remote, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fail(err)
	}

	// An unbound local socket: the PHP side is listening, so only the remote address matters.
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		fail(err)
	}
	defer socket.Close()

	emit(event{
		Event:       "listening",
		Port:        socket.LocalAddr().(*net.UDPAddr).Port,
		Fingerprint: certificateFingerprint(cert),
	})

	conn, err := dtls.Client(socket, remote, cfg)
	if err != nil {
		fail(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := conn.HandshakeContext(ctx); err != nil {
		fail(err)
	}

	report(conn)
	echo(conn)
}

func main() {
	role := flag.String("role", "server", "server or client")
	addr := flag.String("addr", "", "address to dial when role=client")
	profiles := flag.String("srtp", "", "comma separated SRTP protection profiles to offer")
	timeout := flag.Duration("timeout", 20*time.Second, "handshake timeout")
	flag.Parse()

	cfg, cert, err := buildConfig(*profiles)
	if err != nil {
		fail(err)
	}

	switch *role {
	case "server":
		runServer(cfg, cert, *timeout)
	case "client":
		if *addr == "" {
			fail(fmt.Errorf("role=client needs -addr"))
		}
		runClient(cfg, cert, *addr, *timeout)
	default:
		fail(fmt.Errorf("unknown role %q", *role))
	}
}
