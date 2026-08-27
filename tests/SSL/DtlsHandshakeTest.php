<?php

namespace Tests\Webrtc\DTLS\SSL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Webrtc\DTLS\DtlsPeer;
use Tests\Webrtc\SSLPeer;
use Webrtc\DTLS\DTLS\Engine;
use Webrtc\DTLS\DTLS\RTCCertificate;
use Webrtc\DTLS\Enum\BioMethod;
use Webrtc\DTLS\Enum\ContextMethod;
use Webrtc\DTLS\SSL\BIO;
use Webrtc\DTLS\SSL\Context;
use Webrtc\DTLS\SSL\SSL;

/**
 * Completes a real DTLS 1.2 handshake against pion/dtls, in both roles.
 *
 * The previous suite exercised the OpenSSL binding this package used to be, so it stopped
 * compiling the moment DTLS was reimplemented in PHP and left the handshake with no coverage
 * at all. Handshaking against a real peer is the only check that actually means something
 * here: the two halves of this codebase will agree with each other no matter what they put
 * on the wire.
 */
#[CoversClass(SSL::class)]
#[CoversClass(Engine::class)]
#[UsesClass(BIO::class)]
#[UsesClass(Context::class)]
#[UsesClass(\Webrtc\DTLS\DTLS\Handshake::class)]
#[UsesClass(\Webrtc\DTLS\DTLS\Prf::class)]
#[UsesClass(\Webrtc\DTLS\DTLS\RTCCertificate::class)]
#[UsesClass(\Webrtc\DTLS\DTLS\Reader::class)]
#[UsesClass(\Webrtc\DTLS\DTLS\RecordLayer::class)]
class DtlsHandshakeTest extends TestCase
{
    private ?DtlsPeer $peer = null;

    /** @var resource|null */
    private $socket = null;

    /** The engine's datagram queues, which the test pumps to and from the socket itself. */
    private ?BIO $bio = null;

    protected function tearDown(): void
    {
        $this->peer?->stop();
        $this->peer = null;

        if (\is_resource($this->socket)) {
            fclose($this->socket);
        }
        $this->socket = null;
        $this->bio = null;

        parent::tearDown();
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function srtpProfiles(): array
    {
        return [
            // The names differ on each side: pion spells the counter-mode profile with the
            // HMAC in it, this package does not.
            'AES128_CM_SHA1_80' => ['SRTP_AES128_CM_HMAC_SHA1_80', 'SRTP_AES128_CM_SHA1_80'],
            'AEAD_AES_128_GCM' => ['SRTP_AEAD_AES_128_GCM', 'SRTP_AEAD_AES_128_GCM'],
            'AEAD_AES_256_GCM' => ['SRTP_AEAD_AES_256_GCM', 'SRTP_AEAD_AES_256_GCM'],
        ];
    }

    #[DataProvider('srtpProfiles')]
    public function testHandshakesAsClientAgainstTheReferenceServer(
        string $pionProfile,
        string $ourProfile
    ): void {
        $this->peer = DtlsPeer::locate();
        $listening = $this->peer->start('server', $pionProfile);

        $this->socket = $this->openSocket();
        $remote = "127.0.0.1:{$listening['port']}";

        $ssl = $this->newSsl($ourProfile);
        $ssl->setConnectState();

        $this->handshake($ssl, $remote);

        $connected = $this->peer->await('connected');

        $this->assertSame(
            $ourProfile,
            $ssl->getSelectedSrtpProfile(),
            'both sides must settle on the same SRTP protection profile'
        );

        $this->assertSame(
            $connected['keyingMaterial'],
            bin2hex($ssl->exportKeyingMaterial('EXTRACTOR-dtls_srtp', 88)),
            'the exported SRTP keying material must match the reference implementation'
        );
    }

    #[DataProvider('srtpProfiles')]
    public function testHandshakesAsServerAgainstTheReferenceClient(
        string $pionProfile,
        string $ourProfile
    ): void {
        // Bind first: the peer needs somewhere to dial.
        $this->socket = $this->openSocket();
        $local = stream_socket_get_name($this->socket, false);

        $this->peer = DtlsPeer::locate();
        $this->peer->start('client', $pionProfile, $local);

        $ssl = $this->newSsl($ourProfile);
        $ssl->setAcceptState();

        $this->handshake($ssl, null);

        $connected = $this->peer->await('connected');

        $this->assertSame($ourProfile, $ssl->getSelectedSrtpProfile());
        $this->assertSame(
            $connected['keyingMaterial'],
            bin2hex($ssl->exportKeyingMaterial('EXTRACTOR-dtls_srtp', 88))
        );
    }

    /**
     * Application data has to survive the protected path in both directions.
     */
    public function testExchangesApplicationDataWithTheReferenceServer(): void
    {
        $this->peer = DtlsPeer::locate();
        $listening = $this->peer->start('server', 'SRTP_AES128_CM_HMAC_SHA1_80');

        $this->socket = $this->openSocket();
        $remote = "127.0.0.1:{$listening['port']}";

        $ssl = $this->newSsl('SRTP_AES128_CM_SHA1_80');
        $ssl->setConnectState();
        $this->handshake($ssl, $remote);
        $this->peer->await('connected');

        $ssl->write('hello dtls');
        $this->flush($remote);
        $this->peer->await('echo');

        $this->assertSame('hello dtls', $this->readApplicationData($ssl, $remote));
    }

    /**
     * The peer's certificate is authenticated by fingerprint in WebRTC, so the digest this
     * side computes has to be the one the peer publishes.
     */
    public function testReportsThePeerCertificateFingerprint(): void
    {
        $this->peer = DtlsPeer::locate();
        $listening = $this->peer->start('server', 'SRTP_AES128_CM_HMAC_SHA1_80');

        $this->socket = $this->openSocket();
        $ssl = $this->newSsl('SRTP_AES128_CM_SHA1_80');
        $ssl->setConnectState();
        $this->handshake($ssl, "127.0.0.1:{$listening['port']}");

        $digest = $ssl->getPeerCertificateDigest();
        $this->assertNotNull($digest);
        $this->assertSame(
            strtoupper($listening['fingerprint']),
            strtoupper($digest),
            'the SHA-256 digest must match the certificate the peer actually presented'
        );
    }

    private function newSsl(?string $srtpProfile): SSL
    {
        $context = new Context(ContextMethod::DTLS_METHOD);
        $context->setCertificate(new RTCCertificate());
        if ($srtpProfile !== null) {
            $context->setTlsextUseSrtp($srtpProfile);
        }

        $this->bio = new BIO(BioMethod::s_mem);

        return new SSL($context, $this->bio);
    }

    /**
     * @return resource
     */
    private function openSocket()
    {
        $socket = stream_socket_server('udp://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND);
        if ($socket === false) {
            throw new RuntimeException("Could not bind a UDP socket: $errstr");
        }
        stream_set_blocking($socket, false);

        return $socket;
    }

    /**
     * Pump datagrams until the handshake completes.
     *
     * The engine is driven synchronously here rather than through the event loop: this suite
     * is about the records on the wire, and a loop would only add a way for the test to hang.
     */
    private function handshake(SSL $ssl, ?string $remote, float $timeout = 20.0): void
    {
        $deadline = microtime(true) + $timeout;

        while (microtime(true) < $deadline) {
            if ($ssl->doHandshake()) {
                $this->flush($remote);

                return;
            }

            $remote = $this->flush($remote);
            $remote = $this->receive($remote) ?? $remote;

            // Retransmit whenever the engine says its flight timer has expired, which is what
            // keeps the exchange moving if a datagram was dropped.
            if (($due = $ssl->dtlsV1GetTimeout()) !== null && $due <= 0.0) {
                $ssl->dtlsV1HandleTimeout();
            }
        }

        throw new RuntimeException('The DTLS handshake did not complete in time.');
    }

    /**
     * Send everything the engine has queued, returning the address in use.
     */
    private function flush(?string $remote): ?string
    {
        if ($remote === null) {
            return null;
        }

        while (($datagram = $this->bio->read()) !== null) {
            stream_socket_sendto($this->socket, $datagram, 0, $remote);
        }

        return $remote;
    }

    /**
     * Read whatever has arrived, learning the peer's address on the first datagram when this
     * side is the one being dialled.
     */
    private function receive(?string $remote): ?string
    {
        $read = [$this->socket];
        $write = $except = [];

        if (stream_select($read, $write, $except, 0, 50_000) < 1) {
            return $remote;
        }

        $datagram = stream_socket_recvfrom($this->socket, 65535, 0, $peer);
        if ($datagram === false || $datagram === '') {
            return $remote;
        }

        $this->bio->write($datagram);

        return $remote ?? $peer;
    }

    private function readApplicationData(SSL $ssl, ?string $remote, float $timeout = 5.0): string
    {
        $deadline = microtime(true) + $timeout;

        while (microtime(true) < $deadline) {
            $this->receive($remote);

            $data = $ssl->readApplicationData();
            if ($data !== null) {
                return $data;
            }
        }

        throw new RuntimeException('The peer never echoed the application data back.');
    }
}
