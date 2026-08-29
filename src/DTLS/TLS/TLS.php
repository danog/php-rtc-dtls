<?php

/**
 * This file is part of the PHP WebRTC package.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\DTLS\DTLS\TLS;

use Psr\Log\LoggerInterface;
use Webrtc\DTLS\DTLS\Enum\SSLHandshakeState;
use Webrtc\DTLS\DTLS\Exception\TLSException;
use Webrtc\DTLS\DTLS\RTCCertificate;
use Webrtc\DTLS\DTLS\Srtp;
use Webrtc\ICE\RTCIceTransportInterface;
use Webrtc\SDP\DtlsParameter\RTCDtlsFingerprint;
use Webrtc\Srtp\Exception\SrtpException;
use Webrtc\DTLS\Enum\BioMethod;
use Webrtc\DTLS\Enum\ContextMethod;
use Webrtc\DTLS\Enum\Verify;
use Webrtc\DTLS\Exception\OpenSSLException;
use Webrtc\DTLS\Exception\SSLException;
use Webrtc\DTLS\Exception\SysCallException;
use Webrtc\DTLS\Exception\ZeroReturnException;
use Webrtc\DTLS\SSL\BIO;
use Webrtc\DTLS\SSL\BIOInterface;
use Webrtc\DTLS\SSL\Context;
use Webrtc\DTLS\SSL\SSL;
use Webrtc\DTLS\SSL\SSLInterface;
use Webrtc\Stats\enum\TLSState;

/**
 * Class TLS
 *
 * Manages DTLS/TLS connections for WebRTC, providing encryption, decryption, and handshake functionality.
 * This class encapsulates the OpenSSL operations needed for secure communication over WebRTC data channels.
 *
 * Key responsibilities:
 * - Managing the TLS/DTLS connection state
 * - Performing encryption and decryption of data
 * - Handling the DTLS handshake process
 * - Validating peer certificates
 * - Managing SRTP (Secure Real-time Transport Protocol) profiles
 * - Exporting keying material for SRTP
 *
 * @package Webrtc\DTLS\DTLS\TLS
 */
final class TLS
{
    /** @var array Supported cipher suites for the TLS connection */
    private const SUPPORTED_CIPHER_SUITES = [
        // AES-128-GCM-SHA256
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",

        // AES-256-CBC-SHA
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-RSA-AES256-SHA",

        // AES-256-GCM-SHA384
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384"
    ];

    /** @var SSLInterface The SSL connection instance */
    private SSLInterface $ssl;

    /** @var Context The SSL context */
    private Context $context;

    /** @var BIO The BIO buffer for SSL operations */
    private BIO $bio;

    /** @var TLSState Current state of the TLS connection */
    private TLSState $state = TLSState::NEW;

    /** @var LoggerInterface|null Optional logger for debugging */
    private ?LoggerInterface $logger = null;

    /**
     * TLS constructor.
     *
     * Initializes the TLS instance with the provided certificate and sets up the SSL context,
     * BIO buffer, and SSL connection.
     *
     * @param RTCCertificate $certificate The certificate to use for this TLS connection
     * @throws OpenSSLException If OpenSSL initialization fails
     * @throws SrtpException If SRTP profile setup fails
     */
    public function __construct(private readonly RTCCertificate $certificate)
    {
        $this->context = $this->createContext();
        $this->bio = $this->createBIO();
        $this->ssl = $this->createSSL();
    }

    /**
     * Starts the DTLS handshake process.
     *
     * Creates a new Handshake instance and initiates the handshake process with the given transport.
     * The handshake can be either as a client (Connect) or server (Accept).
     *
     * @param RTCIceTransportInterface $transport The ICE transport to use for communication
     * @param SSLHandshakeState $state Whether to initiate as client or server
     * @return void Returns once the handshake has completed.
     */
    public function startHandshaking(RTCIceTransportInterface $transport, SSLHandshakeState $state): void
    {
        $handshake = new Handshake($this, $transport, $state);
        $handshake->do();
    }

    /**
     * Encrypts data using the established TLS connection.
     *
     * @param string $data The plaintext data to encrypt
     * @return string The encrypted data
     * @throws OpenSSLException If an OpenSSL error occurs
     * @throws SysCallException If a system call fails
     * @throws TLSException If the TLS connection is not in the correct state
     * @throws ZeroReturnException If the connection was closed
     * @throws SSLException For general SSL errors
     */
    public function encrypt(string $data): string
    {
        $this->checkState();
        $this->ssl->write($data);
        return (string) $this->bio->read();
    }

    /**
     * Feeds one encrypted datagram into the connection and returns any decrypted application data.
     *
     * @param string $data The encrypted datagram to decrypt
     * @return string|null The decrypted application data, or null if the datagram carried none
     * @throws OpenSSLException If an OpenSSL error occurs
     * @throws SSLException For general SSL errors
     * @throws TLSException If the TLS connection is not in the correct state
     * @throws ZeroReturnException If the connection was closed
     */
    public function decrypt(string $data): ?string
    {
        $this->checkState();
        $this->bio->write($data);
        return $this->ssl->readApplicationData();
    }

    /**
     * Factory method to create a new TLS instance.
     *
     * @param RTCCertificate $certificate The certificate to use
     * @return static A new TLS instance
     * @throws OpenSSLException|SrtpException If initialization fails
     */
    public static function create(RTCCertificate $certificate): static
    {
        return new static($certificate);
    }

    /**
     * Validates the peer's certificate against provided fingerprints.
     *
     * @param RTCDtlsFingerprint[] $peerCerts Array of peer certificate fingerprints to validate against
     * @return bool True if the peer's certificate matches one of the provided fingerprints
     * @throws OpenSSLException If certificate validation fails
     * @throws TLSException If the TLS connection is not in the correct state
     */
    public function validatePeerCertificate(array $peerCerts): bool
    {
        $this->checkState();
        $peerCertDigits = $this->ssl->getPeerCertificateDigest();

        return array_any($peerCerts, fn(RTCDtlsFingerprint $cert) => $cert->isAlgorithm("sha-256") && strtolower($cert->value) === strtolower($peerCertDigits ?? ''));
    }

    /**
     * Exports keying material for SRTP.
     *
     * @param int $keyLength Length of the key material needed
     * @param int $saltLent Length of the salt needed
     * @return string The exported keying material
     * @throws OpenSSLException If key export fails
     * @throws TLSException If the TLS connection is not in the correct state
     */
    public function exportKeyingMaterial(int $keyLength, int $saltLent): string
    {
        $this->checkState();
        return $this->ssl->exportKeyingMaterial("EXTRACTOR-dtls_srtp", 2 * ($keyLength + $saltLent));
    }

    /**
     * Gets the selected SRTP protection profile.
     *
     * @return string The name of the selected SRTP profile
     * @throws TLSException If the TLS connection is not in the correct state
     */
    public function getSelectedSrtpProfile(): string
    {
        $this->checkState();
        return $this->ssl->getSelectedSrtpProfile();
    }

    /**
     * Creates the SSL context for the connection.
     *
     * @return Context The created SSL context
     * @throws SrtpException If SRTP profile setup fails
     */
    private function createContext(): Context
    {
        $ctx = new Context(ContextMethod::DTLS_METHOD);
        $ctx->setVerify(Verify::PEER->value | Verify::FAIL_IF_NO_PEER_CERT->value, fn(mixed ...$args): bool => true);
        $ctx->setCipherList(implode(":", self::SUPPORTED_CIPHER_SUITES));
        $ctx->setTlsextUseSrtp(implode(":", array_map(static fn(array $profile): string => $profile["sslProfile"], Srtp::getProfiles())));
        $this->setCertAndPrivateKey($ctx);
        $this->setLoggerInfo($ctx);

        return $ctx;
    }

    /**
     * Creates the SSL connection instance.
     *
     * @return SSL The created SSL connection
     */
    private function createSSL(): SSL
    {
        return new SSL($this->context, $this->bio);
    }

    /**
     * Creates the BIO buffer for SSL operations.
     *
     * @return BIO The created BIO buffer
     */
    private function createBIO(): BIO
    {
        $method = BioMethod::s_mem;
        $bio = new BIO($method);

        return $bio;
    }

    /**
     * Shuts down the SSL connection gracefully.
     *
     * @return bool True if shutdown was successful
     * @throws OpenSSLException If an OpenSSL error occurs
     * @throws SSLException For general SSL errors
     * @throws SysCallException If a system call fails
     * @throws ZeroReturnException If the connection was closed
     */
    public function shutdown(): bool
    {
        if ($this->ssl->shutdown()) {
            $this->setState(TLSState::CLOSED);
            return true;
        }

        return false;
    }

    /**
     * Gets the SSL connection instance.
     *
     * @return SSLInterface The SSL connection
     */
    public function getSsl(): SSLInterface
    {
        return $this->ssl;
    }

    /**
     * Gets the BIO buffer instance.
     *
     * @return BIOInterface The BIO buffer
     */
    public function getBio(): BIOInterface
    {
        return $this->bio;
    }

    /**
     * Gets the current TLS connection state.
     *
     * @return TLSState The current state
     */
    public function getState(): TLSState
    {
        return $this->state;
    }

    /**
     * Sets the TLS connection state.
     *
     * @param TLSState $state The new state to set
     */
    public function setState(TLSState $state): void
    {
        $this->state = $state;
    }

    /**
     * Verifies that the TLS connection is in the correct state for operations.
     *
     * @throws TLSException If the connection is not in the CONNECTED state
     */
    private function checkState(): void
    {
        if ($this->state !== TLSState::CONNECTED) {
            throw new TLSException("TLS is not connected");
        }
    }

    /**
     * Configures the certificate and private key in the SSL context.
     *
     * @param Context $ctx The SSL context to configure
     */
    private function setCertAndPrivateKey(Context $ctx): void
    {
        $ctx->setCertificate($this->certificate);
    }

    /**
     * Configures logging for the SSL context if a logger is set.
     *
     * @param Context $ctx The SSL context to configure
     */
    private function setLoggerInfo(Context $ctx): void
    {
        // Currently commented out - would enable logging if logger is set
        if ($this->logger) {
            $ctx->setInfoCallBack($this->logger);
        }
    }

    /**
     * Sets the logger for this TLS instance.
     *
     * @param LoggerInterface|null $logger The logger instance or null to disable logging
     */
    public function setLogger(?LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }
}