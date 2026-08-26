<?php

/**
 * This file is part of the PHP WebRTC package, vendored and modified for MadelineProto.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\DTLS\DTLS;

use Webrtc\DTLS\DTLS\RTCCertificate;
use Webrtc\DTLS\Exception\SSLException;
use phpseclib3\Crypt\DH;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\File\X509;
use Throwable;

/**
 * A DTLS 1.2 handshake state machine, in pure PHP.
 *
 * Only what WebRTC actually needs is implemented: DTLS 1.2, ECDHE over P-256, AES-128-GCM, mutual
 * authentication with self-signed certificates and the `use_srtp` extension (RFC 5764). The peer's
 * certificate is *not* validated against a chain of trust, because WebRTC pins it by fingerprint
 * through the signalling channel; what does get verified is that the peer holds the matching
 * private key, via its CertificateVerify signature.
 *
 * The engine is transport agnostic: {@see self::handleDatagram()} takes bytes off the wire and
 * {@see self::takeOutgoing()} hands back datagrams to send.
 */
final class Engine
{
    /** TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256. */
    public const SUITE_ECDHE_ECDSA_AES128_GCM = 0xC02B;
    /** TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256. */
    public const SUITE_ECDHE_RSA_AES128_GCM = 0xC02F;

    private const CURVE_SECP256R1 = 23;
    private const SIG_ECDSA_SECP256R1_SHA256 = 0x0403;
    private const SIG_RSA_PKCS1_SHA256 = 0x0401;

    private const EXT_SUPPORTED_GROUPS = 10;
    private const EXT_EC_POINT_FORMATS = 11;
    private const EXT_SIGNATURE_ALGORITHMS = 13;
    private const EXT_USE_SRTP = 14;
    private const EXT_EXTENDED_MASTER_SECRET = 23;
    private const EXT_RENEGOTIATION_INFO = 0xFF01;

    /** DER prefix of a SubjectPublicKeyInfo holding an uncompressed P-256 point. */
    private const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

    private const AES_KEY_LENGTH = 16;
    private const AEAD_SALT_LENGTH = 4;

    /** Initial retransmission timeout, doubled on each expiry (RFC 6347 section 4.2.4.1). */
    private const INITIAL_TIMEOUT = 1.0;
    private const MAX_TIMEOUT = 60.0;

    private RecordLayer $records;
    private Handshake $reassembler;

    private bool $isServer = false;
    private bool $started = false;
    private bool $handshakeComplete = false;
    private bool $closed = false;

    /**
     * Whether this side has already put its own close_notify on the wire.
     *
     * Tracked separately from $closed, which is also set when the *peer* closes: a peer that
     * announces a close still has to be answered with our own alert before the association is
     * torn down, and conflating the two swallows that reply.
     */
    private bool $closeNotifySent = false;

    private string $clientRandom = '';
    private string $serverRandom = '';
    private string $cookie = '';
    private int $cipherSuite = self::SUITE_ECDHE_ECDSA_AES128_GCM;

    private ?EC\PrivateKey $ecdhePrivate = null;
    private string $masterSecret = '';
    /** The peer's ECDHE public point, kept until we are ready to derive the master secret. */
    private string $peerEcdhePoint = '';
    /** Whether both sides agreed on RFC 7627 extended master secret. */
    private bool $extendedMasterSecret = false;
    /** Whether the peer offered RFC 7627, which decides whether we echo the extension back. */
    private bool $peerOfferedExtendedMasterSecret = false;

    /** Every handshake message exchanged so far, in unfragmented form. */
    private string $transcript = '';

    /** Sequence number of the next handshake message we send. */
    private int $writeMessageSeq = 0;

    /** Datagrams waiting to be sent. @var list<string> */
    private array $outgoing = [];
    /**
     * The last flight we sent, kept for retransmission as plaintext records.
     *
     * @var list<array{int, string, int}> Record type, payload and the epoch it was sent in.
     */
    private array $lastFlight = [];

    /** Plaintext application data received from the peer. */
    private string $incomingApplicationData = '';

    private ?string $peerCertificate = null;
    private ?string $peerCertificateDigest = null;
    private string $selectedSrtpProfile = '';

    /** Every SRTP protection profile this engine implements, most preferred first. */
    private const SUPPORTED_SRTP_PROFILES = [
        'SRTP_AEAD_AES_256_GCM' => 0x0008,
        'SRTP_AEAD_AES_128_GCM' => 0x0007,
        'SRTP_AES128_CM_SHA1_80' => 0x0001,
    ];

    /** SRTP protection profiles we offer, most preferred first. @var array<string, int> */
    private array $srtpProfiles = self::SUPPORTED_SRTP_PROFILES;

    private float $timeout = self::INITIAL_TIMEOUT;
    private ?float $deadline = null;

    /**
     * @param list<string> $srtpProfiles The protection profiles to offer, most preferred first.
     *                                   Empty offers everything this engine implements.
     */
    public function __construct(
        private readonly RTCCertificate $certificate,
        array $srtpProfiles = []
    ) {
        $this->records = new RecordLayer;
        $this->reassembler = new Handshake;

        if ($srtpProfiles !== []) {
            $requested = array_intersect_key(
                self::SUPPORTED_SRTP_PROFILES,
                array_flip($srtpProfiles)
            );

            if ($requested === []) {
                throw new SSLException(
                    'None of the requested SRTP protection profiles are implemented: '
                    . implode(', ', $srtpProfiles)
                );
            }

            $this->srtpProfiles = $requested;
        }
    }

    /**
     * Act as the DTLS server, i.e. wait for the peer's ClientHello.
     */
    public function setAcceptState(): void
    {
        $this->isServer = true;
    }

    /**
     * Act as the DTLS client, i.e. drive the handshake.
     */
    public function setConnectState(): void
    {
        $this->isServer = false;
    }

    public function isServer(): bool
    {
        return $this->isServer;
    }

    public function isHandshakeComplete(): bool
    {
        return $this->handshakeComplete;
    }

    /**
     * Advance the handshake, sending the first flight if we are the client.
     */
    public function startHandshake(): void
    {
        if ($this->started || $this->isServer) {
            $this->started = true;
            return;
        }
        $this->started = true;
        $this->clientRandom = self::random32();
        $this->sendFlight([[Handshake::CLIENT_HELLO, $this->buildClientHello()]]);
    }

    /**
     * Take the datagrams the engine wants to send.
     *
     * @return list<string>
     */
    public function takeOutgoing(): array
    {
        $out = $this->outgoing;
        $this->outgoing = [];
        return $out;
    }

    /**
     * Whether any datagram is waiting to be sent.
     */
    public function hasOutgoing(): bool
    {
        return $this->outgoing !== [];
    }

    /**
     * Seconds until the current flight should be retransmitted, or null if no timer is armed.
     */
    public function getTimeout(): ?float
    {
        if ($this->deadline === null || $this->handshakeComplete) {
            return null;
        }
        return max(0.0, $this->deadline - microtime(true));
    }

    /**
     * Retransmit the last flight if the timer expired.
     */
    public function handleTimeout(): bool
    {
        if ($this->deadline === null || $this->handshakeComplete) {
            return false;
        }
        if (microtime(true) < $this->deadline) {
            return false;
        }
        $this->timeout = min($this->timeout * 2, self::MAX_TIMEOUT);
        $this->deadline = microtime(true) + $this->timeout;
        $this->queueLastFlight();
        return true;
    }

    /**
     * Encode the remembered flight afresh and queue it for sending.
     *
     * Each record is re-encoded at the epoch it was originally sent in but with a new sequence
     * number, as RFC 6347 section 4.2.1 requires: replaying the original numbers would see the
     * whole flight discarded by the peer's duplicate detection.
     */
    private function queueLastFlight(): void
    {
        foreach ($this->lastFlight as [$type, $payload, $epoch]) {
            $this->outgoing[] = $this->records->encode($type, $payload, null, $epoch);
        }
    }

    /**
     * Process one datagram received from the peer.
     *
     * @throws SSLException On a fatal protocol violation.
     */
    public function handleDatagram(string $datagram): void
    {
        foreach ($this->records->decode($datagram) as $record) {
            switch ($record['type']) {
                case RecordLayer::TYPE_HANDSHAKE:
                    if ($this->handshakeComplete) {
                        // Completing the handshake clears the retransmission deadline, so our
                        // final flight is never re-sent on a timer. A peer still sending
                        // handshake records is telling us that flight never arrived; RFC 6347
                        // section 4.2.4 requires answering with it again. Without this the peer
                        // retransmits until it gives up while we consider the exchange finished.
                        $this->queueLastFlight();
                        break;
                    }

                    foreach ($this->reassembler->receive($record['payload']) as $message) {
                        $this->handleHandshakeMessage($message['type'], $message['body'], $message['seq']);
                    }
                    break;
                case RecordLayer::TYPE_CHANGE_CIPHER_SPEC:
                    // The record layer already advanced the read epoch while decoding.
                    break;
                case RecordLayer::TYPE_APPLICATION_DATA:
                    $this->incomingApplicationData .= $record['payload'];
                    break;
                case RecordLayer::TYPE_ALERT:
                    $this->handleAlert($record['payload']);
                    break;
            }
        }
    }

    /**
     * @throws SSLException If the peer reported a fatal condition.
     */
    private function handleAlert(string $payload): void
    {
        if (\strlen($payload) < 2) {
            return;
        }
        $level = \ord($payload[0]);
        $description = \ord($payload[1]);
        if ($description === 0) {
            // close_notify
            $this->closed = true;
            return;
        }
        if ($level === 2) {
            $this->closed = true;
            throw new SSLException("The peer sent a fatal DTLS alert: $description");
        }
    }

    /**
     * Encrypt application data for the peer.
     *
     * @throws SSLException If the handshake is not finished.
     */
    public function write(string $data): void
    {
        if (!$this->handshakeComplete) {
            throw new SSLException('Cannot write application data before the handshake completes!');
        }
        $this->outgoing[] = $this->records->encode(RecordLayer::TYPE_APPLICATION_DATA, $data);
    }

    /**
     * Read whatever application data arrived so far.
     */
    public function read(int $length): string
    {
        $data = substr($this->incomingApplicationData, 0, $length);
        $this->incomingApplicationData = substr($this->incomingApplicationData, \strlen($data));
        return $data;
    }

    public function pendingApplicationData(): int
    {
        return \strlen($this->incomingApplicationData);
    }

    /**
     * Send a close_notify alert.
     */
    public function shutdown(): bool
    {
        if ($this->closeNotifySent) {
            return true;
        }
        $this->closeNotifySent = true;
        $this->closed = true;
        $this->outgoing[] = $this->records->encode(RecordLayer::TYPE_ALERT, "\x01\x00");
        return true;
    }

    public function isClosed(): bool
    {
        return $this->closed;
    }

    /**
     * The SHA-256 fingerprint of the peer's certificate, colon separated and uppercase.
     */
    public function getPeerCertificateDigest(): ?string
    {
        return $this->peerCertificateDigest;
    }

    /**
     * The SRTP protection profile both sides agreed on, as its RFC 5764 name.
     */
    public function getSelectedSrtpProfile(): string
    {
        return $this->selectedSrtpProfile;
    }

    /**
     * Export keying material as defined in RFC 5705.
     *
     * @throws SSLException If the handshake is not finished.
     */
    public function exportKeyingMaterial(string $label, int $length, ?string $context = null): string
    {
        if (!$this->handshakeComplete) {
            throw new SSLException('Cannot export keying material before the handshake completes!');
        }
        return Prf::exportKeyingMaterial(
            $this->masterSecret,
            $label,
            $this->clientRandom,
            $this->serverRandom,
            $length,
            $context
        );
    }

    // ---------------------------------------------------------------- handshake

    /**
     * @throws SSLException On a fatal protocol violation.
     */
    private function handleHandshakeMessage(int $type, string $body, int $seq): void
    {
        // HelloVerifyRequest is excluded from the transcript (RFC 6347 section 4.2.1).
        if ($type !== Handshake::HELLO_VERIFY_REQUEST) {
            $this->transcript .= Handshake::transcriptForm($type, $body, $seq);
        }

        match (true) {
            $type === Handshake::CLIENT_HELLO && $this->isServer => $this->onClientHello($body),
            $type === Handshake::HELLO_VERIFY_REQUEST && !$this->isServer => $this->onHelloVerifyRequest($body),
            $type === Handshake::SERVER_HELLO && !$this->isServer => $this->onServerHello($body),
            $type === Handshake::CERTIFICATE => $this->onCertificate($body),
            $type === Handshake::SERVER_KEY_EXCHANGE && !$this->isServer => $this->onServerKeyExchange($body),
            $type === Handshake::CERTIFICATE_REQUEST && !$this->isServer => null,
            $type === Handshake::SERVER_HELLO_DONE && !$this->isServer => $this->onServerHelloDone(),
            $type === Handshake::CLIENT_KEY_EXCHANGE && $this->isServer => $this->onClientKeyExchange($body),
            $type === Handshake::CERTIFICATE_VERIFY => $this->onCertificateVerify($body),
            $type === Handshake::FINISHED => $this->onFinished($body),
            default => null,
        };
    }

    /**
     * @throws SSLException If the client offers nothing we support.
     */
    private function onClientHello(string $body): void
    {
        $reader = new Reader($body);
        $reader->skip(2); // client_version
        $this->clientRandom = $reader->take(32);
        $reader->takeVector8(); // session_id
        $this->cookie = $reader->takeVector8();

        $suites = $reader->takeVector16();
        $this->cipherSuite = $this->pickCipherSuite($suites);

        $reader->takeVector8(); // compression_methods
        $extensions = self::parseExtensions($reader->rest());
        $this->negotiateSrtpProfile($extensions[self::EXT_USE_SRTP] ?? null);
        $this->peerOfferedExtendedMasterSecret = isset($extensions[self::EXT_EXTENDED_MASTER_SECRET]);
        $this->extendedMasterSecret = $this->peerOfferedExtendedMasterSecret;

        $this->serverRandom = self::random32();
        $this->ecdhePrivate = EC::createKey('secp256r1');

        // The transcript restarts from this ClientHello; anything before it was a cookie exchange.
        $this->sendFlight([
            [Handshake::SERVER_HELLO, $this->buildServerHello()],
            [Handshake::CERTIFICATE, $this->buildCertificate()],
            [Handshake::SERVER_KEY_EXCHANGE, $this->buildServerKeyExchange()],
            [Handshake::CERTIFICATE_REQUEST, $this->buildCertificateRequest()],
            [Handshake::SERVER_HELLO_DONE, ''],
        ]);
    }

    /**
     * @throws SSLException If no mutually supported cipher suite exists.
     */
    private function pickCipherSuite(string $suites): int
    {
        $offered = [];
        for ($i = 0; $i + 1 < \strlen($suites); $i += 2) {
            $offered[] = unpack('n', substr($suites, $i, 2))[1];
        }
        foreach ([self::SUITE_ECDHE_ECDSA_AES128_GCM, self::SUITE_ECDHE_RSA_AES128_GCM] as $candidate) {
            if (\in_array($candidate, $offered, true)) {
                return $candidate;
            }
        }
        throw new SSLException('The peer does not support any cipher suite we implement!');
    }

    private function onHelloVerifyRequest(string $body): void
    {
        $reader = new Reader($body);
        $reader->skip(2); // server_version
        $this->cookie = $reader->takeVector8();

        // The cookie exchange is not part of the transcript: start over with the new ClientHello.
        $this->transcript = '';
        $this->sendFlight([[Handshake::CLIENT_HELLO, $this->buildClientHello()]]);
    }

    /**
     * @throws SSLException If the server picked something we did not offer.
     */
    private function onServerHello(string $body): void
    {
        $reader = new Reader($body);
        $reader->skip(2); // server_version
        $this->serverRandom = $reader->take(32);
        $reader->takeVector8(); // session_id
        $this->cipherSuite = unpack('n', $reader->take(2))[1];
        $reader->skip(1); // compression_method

        if ($this->cipherSuite !== self::SUITE_ECDHE_ECDSA_AES128_GCM
            && $this->cipherSuite !== self::SUITE_ECDHE_RSA_AES128_GCM) {
            throw new SSLException('The peer selected an unsupported cipher suite!');
        }

        $extensions = self::parseExtensions($reader->rest());
        $this->negotiateSrtpProfile($extensions[self::EXT_USE_SRTP] ?? null);
        $this->extendedMasterSecret = isset($extensions[self::EXT_EXTENDED_MASTER_SECRET]);
    }

    private function onCertificate(string $body): void
    {
        $reader = new Reader($body);
        $listLength = Handshake::uint24($reader->take(3));
        if ($listLength === 0) {
            return;
        }
        $certLength = Handshake::uint24($reader->take(3));
        $this->peerCertificate = $reader->take($certLength);
        $this->peerCertificateDigest = RTCCertificate::fingerprint($this->peerCertificate);
    }

    /**
     * @throws SSLException If the key exchange is malformed or unsupported.
     */
    private function onServerKeyExchange(string $body): void
    {
        $reader = new Reader($body);
        $curveType = \ord($reader->take(1));
        if ($curveType !== 3) {
            throw new SSLException('Only named curves are supported in the key exchange!');
        }
        $curve = unpack('n', $reader->take(2))[1];
        if ($curve !== self::CURVE_SECP256R1) {
            throw new SSLException('Only the secp256r1 curve is supported!');
        }
        $point = $reader->takeVector8();
        $signatureAlgorithm = unpack('n', $reader->take(2))[1];
        $signature = $reader->takeVector16();

        $params = \chr(3).pack('n', self::CURVE_SECP256R1).\chr(\strlen($point)).$point;
        $this->verifyPeerSignature(
            $this->clientRandom.$this->serverRandom.$params,
            $signature,
            $signatureAlgorithm
        );

        $this->ecdhePrivate = EC::createKey('secp256r1');
        $this->peerEcdhePoint = $point;
    }

    private function onServerHelloDone(): void
    {
        \assert($this->ecdhePrivate !== null);
        $point = $this->ecdhePrivate->getPublicKey()->getEncodedCoordinates();

        $messages = [
            [Handshake::CERTIFICATE, $this->buildCertificate()],
            [Handshake::CLIENT_KEY_EXCHANGE, \chr(\strlen($point)).$point],
        ];

        // CertificateVerify signs everything sent so far, including our own ClientKeyExchange.
        $transcript = $this->transcript;
        $seq = $this->writeMessageSeq;
        foreach ($messages as [$type, $payload]) {
            $transcript .= Handshake::transcriptForm($type, $payload, $seq++);
        }
        // With RFC 7627 the master secret binds this very transcript, so it can only be derived
        // once our ClientKeyExchange is part of it.
        $this->masterSecret = $this->deriveMasterSecret($this->peerEcdhePoint, $transcript);
        $messages[] = [Handshake::CERTIFICATE_VERIFY, $this->buildCertificateVerify($transcript)];

        $this->sendFlight($messages, true);
    }

    private function onClientKeyExchange(string $body): void
    {
        $reader = new Reader($body);
        $point = $reader->takeVector8();
        // The transcript already contains this ClientKeyExchange, which is exactly the session
        // hash RFC 7627 requires.
        $this->masterSecret = $this->deriveMasterSecret($point, $this->transcript);
    }

    /**
     * @throws SSLException If the peer cannot prove possession of its private key.
     */
    private function onCertificateVerify(string $body): void
    {
        // The signature covers every handshake message before this one.
        $transcript = substr(
            $this->transcript,
            0,
            \strlen($this->transcript) - \strlen(Handshake::transcriptForm(Handshake::CERTIFICATE_VERIFY, $body, 0))
        );

        $reader = new Reader($body);
        $algorithm = unpack('n', $reader->take(2))[1];
        $signature = $reader->takeVector16();

        $this->verifyPeerSignature($transcript, $signature, $algorithm);
    }

    /**
     * @throws SSLException If the peer's Finished does not match our transcript.
     */
    private function onFinished(string $body): void
    {
        // The peer's Finished is itself part of the transcript for *our* Finished, but the
        // verify_data it carries covers everything up to but excluding itself.
        $transcript = substr(
            $this->transcript,
            0,
            \strlen($this->transcript) - \strlen(Handshake::transcriptForm(Handshake::FINISHED, $body, 0))
        );
        // The message we just received was sent by the peer: a server validates the client's
        // Finished, and vice versa.
        $expected = Prf::verifyData($this->masterSecret, hash('sha256', $transcript, true), $this->isServer);
        if (!hash_equals($expected, $body)) {
            throw new SSLException('The peer sent an invalid Finished message!');
        }

        if ($this->isServer) {
            // The server answers with its own ChangeCipherSpec and Finished.
            $this->sendFlight([], true);
        }

        $this->handshakeComplete = true;
        $this->deadline = null;
    }

    /**
     * Serialize a flight of handshake messages, optionally followed by our ChangeCipherSpec.
     *
     * @param list<array{int, string}> $messages
     */
    private function sendFlight(array $messages, bool $finish = false): void
    {
        // The flight is remembered as plaintext records tagged with the epoch they belong to,
        // not as finished datagrams: a retransmission has to be re-encoded so it carries fresh
        // record sequence numbers, which the peer's duplicate filter would otherwise reject.
        $flight = [];

        foreach ($messages as [$type, $body]) {
            $seq = $this->writeMessageSeq++;
            $this->transcript .= Handshake::transcriptForm($type, $body, $seq);
            foreach (Handshake::fragment($type, $body, $seq) as $fragment) {
                $flight[] = [RecordLayer::TYPE_HANDSHAKE, $fragment, $this->records->getWriteEpoch()];
            }
        }

        if ($finish) {
            // ChangeCipherSpec is still sent in the old epoch; only what follows it is protected.
            $flight[] = [RecordLayer::TYPE_CHANGE_CIPHER_SPEC, "\x01", $this->records->getWriteEpoch()];
            $this->records->activateWrite();

            $body = Prf::verifyData($this->masterSecret, hash('sha256', $this->transcript, true), !$this->isServer);
            $seq = $this->writeMessageSeq++;
            $this->transcript .= Handshake::transcriptForm(Handshake::FINISHED, $body, $seq);
            foreach (Handshake::fragment(Handshake::FINISHED, $body, $seq) as $fragment) {
                $flight[] = [RecordLayer::TYPE_HANDSHAKE, $fragment, $this->records->getWriteEpoch()];
            }
        }

        $this->lastFlight = $flight;
        $this->queueLastFlight();
        $this->armTimer();
    }

    private function armTimer(): void
    {
        $this->timeout = self::INITIAL_TIMEOUT;
        $this->deadline = microtime(true) + $this->timeout;
    }

    /**
     * Complete the ECDHE exchange and install the resulting keys.
     */
    private function deriveMasterSecret(string $peerPoint, string $sessionTranscript): string
    {
        \assert($this->ecdhePrivate !== null);
        $peerKey = EC::loadPublicKey(hex2bin(self::P256_SPKI_PREFIX).$peerPoint);
        $preMasterSecret = DH::computeSecret($this->ecdhePrivate, $peerKey);

        $masterSecret = $this->extendedMasterSecret
            ? Prf::extendedMasterSecret($preMasterSecret, hash('sha256', $sessionTranscript, true))
            : Prf::masterSecret($preMasterSecret, $this->clientRandom, $this->serverRandom);

        $keys = Prf::keyBlock(
            $masterSecret,
            $this->clientRandom,
            $this->serverRandom,
            self::AES_KEY_LENGTH,
            self::AEAD_SALT_LENGTH
        );
        if ($this->isServer) {
            $this->records->setKeys($keys['serverKey'], $keys['serverSalt'], $keys['clientKey'], $keys['clientSalt']);
        } else {
            $this->records->setKeys($keys['clientKey'], $keys['clientSalt'], $keys['serverKey'], $keys['serverSalt']);
        }

        return $masterSecret;
    }

    /**
     * @throws SSLException If the signature does not check out.
     */
    private function verifyPeerSignature(string $data, string $signature, int $algorithm): void
    {
        if ($this->peerCertificate === null) {
            throw new SSLException('The peer signed something before sending its certificate!');
        }
        try {
            $x509 = new X509;
            $x509->loadX509($this->peerCertificate);
            $publicKey = $x509->getPublicKey();
            // SignatureAndHashAlgorithm is {hash, signature}: the hash is the high byte.
            $hash = match (($algorithm >> 8) & 0xFF) {
                2 => 'sha1',
                3 => 'sha224',
                4 => 'sha256',
                5 => 'sha384',
                6 => 'sha512',
                default => 'sha256',
            };
            $publicKey = $publicKey->withHash($hash);
            if ($publicKey instanceof EC\PublicKey) {
                $publicKey = $publicKey->withSignatureFormat('ASN1');
            } elseif ($publicKey instanceof RSA\PublicKey) {
                // TLS 1.2 rsa_pkcs1_* signatures use PKCS#1 v1.5, while phpseclib defaults to PSS.
                $publicKey = $publicKey->withPadding(RSA::SIGNATURE_PKCS1);
            }
            $valid = $publicKey->verify($data, $signature);
        } catch (Throwable $e) {
            throw new SSLException('Could not verify the peer signature: '.$e->getMessage(), 0, $e);
        }
        if (!$valid) {
            throw new SSLException('The peer signature is invalid!');
        }
    }

    // ---------------------------------------------------------------- builders

    private function buildClientHello(): string
    {
        return RecordLayer::VERSION_1_2
            .$this->clientRandom
            .\chr(0)
            .\chr(\strlen($this->cookie)).$this->cookie
            .pack('n', 4).pack('nn', self::SUITE_ECDHE_ECDSA_AES128_GCM, self::SUITE_ECDHE_RSA_AES128_GCM)
            .\chr(1).\chr(0)
            .$this->buildExtensions(true);
    }

    private function buildServerHello(): string
    {
        return RecordLayer::VERSION_1_2
            .$this->serverRandom
            .\chr(0)
            .pack('n', $this->cipherSuite)
            .\chr(0)
            .$this->buildExtensions(false);
    }

    private function buildExtensions(bool $client): string
    {
        $extensions = '';

        if ($client) {
            $groups = pack('n', 2).pack('n', self::CURVE_SECP256R1);
            $extensions .= self::extension(self::EXT_SUPPORTED_GROUPS, $groups);
            $extensions .= self::extension(self::EXT_EC_POINT_FORMATS, \chr(1).\chr(0));
            $sigAlgs = pack('n', 4).pack('nn', self::SIG_ECDSA_SECP256R1_SHA256, self::SIG_RSA_PKCS1_SHA256);
            $extensions .= self::extension(self::EXT_SIGNATURE_ALGORITHMS, $sigAlgs);
        }

        if ($client || $this->peerOfferedExtendedMasterSecret) {
            $extensions .= self::extension(self::EXT_EXTENDED_MASTER_SECRET, '');
        }
        $extensions .= self::extension(self::EXT_RENEGOTIATION_INFO, \chr(0));

        // use_srtp: the client offers a list, the server echoes back the single chosen profile.
        if ($client) {
            $profiles = '';
            foreach ($this->srtpProfiles as $id) {
                $profiles .= pack('n', $id);
            }
            $extensions .= self::extension(
                self::EXT_USE_SRTP,
                pack('n', \strlen($profiles)).$profiles.\chr(0)
            );
        } elseif ($this->selectedSrtpProfile !== '') {
            $id = $this->srtpProfiles[$this->selectedSrtpProfile];
            $extensions .= self::extension(self::EXT_USE_SRTP, pack('n', 2).pack('n', $id).\chr(0));
        }

        return pack('n', \strlen($extensions)).$extensions;
    }

    private static function extension(int $type, string $body): string
    {
        return pack('n', $type).pack('n', \strlen($body)).$body;
    }

    private function buildCertificate(): string
    {
        $der = $this->certificate->getDer();
        $entry = Handshake::packUint24(\strlen($der)).$der;
        return Handshake::packUint24(\strlen($entry)).$entry;
    }

    private function buildServerKeyExchange(): string
    {
        \assert($this->ecdhePrivate !== null);
        $point = $this->ecdhePrivate->getPublicKey()->getEncodedCoordinates();
        $params = \chr(3).pack('n', self::CURVE_SECP256R1).\chr(\strlen($point)).$point;

        $signature = $this->certificate->getPrivateKey()
            ->withSignatureFormat('ASN1')
            ->withHash('sha256')
            ->sign($this->clientRandom.$this->serverRandom.$params);

        return $params.pack('n', self::SIG_ECDSA_SECP256R1_SHA256)
            .pack('n', \strlen($signature)).$signature;
    }

    private function buildCertificateRequest(): string
    {
        // certificate_types: ecdsa_sign (64) and rsa_sign (1)
        $types = \chr(2).\chr(64).\chr(1);
        $sigAlgs = pack('n', 4).pack('nn', self::SIG_ECDSA_SECP256R1_SHA256, self::SIG_RSA_PKCS1_SHA256);
        // No acceptable certificate authorities: any self-signed certificate will do.
        return $types.$sigAlgs.pack('n', 0);
    }

    private function buildCertificateVerify(string $transcript): string
    {
        $signature = $this->certificate->getPrivateKey()
            ->withSignatureFormat('ASN1')
            ->withHash('sha256')
            ->sign($transcript);

        return pack('n', self::SIG_ECDSA_SECP256R1_SHA256).pack('n', \strlen($signature)).$signature;
    }

    /**
     * Pick the SRTP profile out of a use_srtp extension.
     */
    private function negotiateSrtpProfile(?string $extension): void
    {
        if ($extension === null || \strlen($extension) < 2) {
            return;
        }
        $length = unpack('n', substr($extension, 0, 2))[1];
        $offered = [];
        for ($i = 0; $i + 1 < $length; $i += 2) {
            $offered[] = unpack('n', substr($extension, 2 + $i, 2))[1];
        }
        foreach ($this->srtpProfiles as $name => $id) {
            if (\in_array($id, $offered, true)) {
                $this->selectedSrtpProfile = $name;
                return;
            }
        }
    }

    /**
     * @return array<int, string> Extension body, keyed by extension type.
     */
    private static function parseExtensions(string $raw): array
    {
        if (\strlen($raw) < 2) {
            return [];
        }
        $total = unpack('n', substr($raw, 0, 2))[1];
        $offset = 2;
        $end = min(\strlen($raw), 2 + $total);
        $extensions = [];
        while ($offset + 4 <= $end) {
            $type = unpack('n', substr($raw, $offset, 2))[1];
            $length = unpack('n', substr($raw, $offset + 2, 2))[1];
            $offset += 4;
            if ($offset + $length > $end) {
                break;
            }
            $extensions[$type] = substr($raw, $offset, $length);
            $offset += $length;
        }
        return $extensions;
    }

    private static function random32(): string
    {
        // The first four bytes are conventionally a timestamp; a random value is equally valid
        // and leaks less.
        return random_bytes(32);
    }
}
