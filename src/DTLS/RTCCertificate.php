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

use Webrtc\DTLS\DTLS\Exception\RTCCertificateException;
use Webrtc\SDP\DtlsParameter\RTCDtlsFingerprint;
use DateTimeImmutable;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PrivateKey;
use phpseclib3\File\X509;
use Throwable;

/**
 * Class RTCCertificate
 *
 * Represents a certificate used by an RTCDtlsTransport for WebRTC communications.
 * This class handles certificate generation, management, and fingerprinting for DTLS connections.
 *
 * Upstream this was generated through OpenSSL's FFI bindings; it now uses phpseclib3, so that a
 * plain PHP installation with no extra extensions can take part in calls. WebRTC certificates are
 * self-signed and pinned by fingerprint, so no chain of trust is involved.
 *
 * The certificate can be either:
 * - Generated automatically with an EC secp256r1 private key (default behavior)
 * - Loaded from existing certificate and private key files
 *
 * @package Webrtc\DTLS\DTLS
 */
final class RTCCertificate
{
    /** @var string Default country for a certificate subject */
    private const COUNTRY = "US";

    /** @var string Default state for a certificate subject */
    private const STATE = "Virginia";

    /** @var string Default city for a certificate subject */
    private const CITY = "Reston";

    /** @var string Default organization for a certificate subject */
    private const ORGANIZATION = "PHP WebRTC";

    /** @var string Default common name for a certificate subject */
    private const ORGANIZATION_WEBSITE = "webrtc.php";

    /** How long the generated certificate stays valid. */
    private const VALIDITY = '+30 days';

    private PrivateKey $privateKey;

    /** The certificate in PEM form. */
    private string $certificate;

    /** The certificate in DER form, which is what goes on the wire and gets fingerprinted. */
    private string $der;

    private DateTimeImmutable $expires;

    /**
     * RTCCertificate constructor.
     *
     * @param string|null $privateKey Path to an existing private key file (PEM format)
     * @param string|null $certificate Path to an existing certificate file (PEM format)
     *
     * @throws RTCCertificateException If provided files don't exist or are invalid.
     */
    public function __construct(?string $privateKey = null, ?string $certificate = null)
    {
        if ($privateKey !== null && $certificate !== null) {
            if (!is_file($privateKey) || !is_file($certificate)) {
                throw new RTCCertificateException(sprintf(
                    "Either the private key file or the certificate file (or both) does not exist. Private key path: %s, Certificate path: %s",
                    $privateKey,
                    $certificate
                ));
            }
            $this->load((string) file_get_contents($privateKey), (string) file_get_contents($certificate));
        } else {
            $this->generate();
        }
    }

    /**
     * @throws RTCCertificateException If the key or certificate cannot be parsed.
     */
    private function load(string $privateKey, string $certificate): void
    {
        try {
            $key = EC::loadPrivateKey($privateKey);
        } catch (Throwable $e) {
            throw new RTCCertificateException('Could not load the private key: '.$e->getMessage(), 0, $e);
        }
        if (!$key instanceof PrivateKey) {
            throw new RTCCertificateException('The provided key is not an EC private key!');
        }
        $this->privateKey = $key;

        $x509 = new X509;
        /** @var array<array-key, mixed>|false $parsed */
        $parsed = $x509->loadX509($certificate);
        if ($parsed === false) {
            throw new RTCCertificateException('Could not parse the certificate!');
        }
        $this->certificate = $certificate;
        $this->der = self::toDer($certificate);
        $this->expires = self::parseExpiry($parsed);
    }

    /**
     * Gets the certificate expiration date.
     */
    public function expires(): DateTimeImmutable
    {
        return $this->expires;
    }

    /**
     * Gets the certificate fingerprints.
     *
     * Returns the SHA-256 digest of the DER encoded certificate, formatted as the colon separated
     * uppercase hex string used by SDP.
     *
     * @return array<RTCDtlsFingerprint> Array of fingerprint objects
     */
    public function getFingerprints(): array
    {
        return [new RTCDtlsFingerprint('sha-256', self::fingerprint($this->der))];
    }

    /**
     * Format the SHA-256 fingerprint of a DER encoded certificate the way SDP expects it.
     */
    public static function fingerprint(string $der): string
    {
        return strtoupper(implode(':', str_split(hash('sha256', $der), 2)));
    }

    /**
     * Generates a new EC secp256r1 key pair and a matching self-signed certificate.
     *
     * @throws RTCCertificateException If generation fails.
     */
    private function generate(): void
    {
        try {
            $key = EC::createKey('secp256r1');
            $this->privateKey = $key;

            $dn = [
                'C' => self::COUNTRY,
                'ST' => self::STATE,
                'L' => self::CITY,
                'O' => self::ORGANIZATION,
                'CN' => self::ORGANIZATION_WEBSITE,
            ];

            $subject = new X509;
            /** @var \phpseclib3\Crypt\Common\PublicKey $subjectPublicKey */
            $subjectPublicKey = $key->getPublicKey();
            $subject->setPublicKey($subjectPublicKey);
            $subject->setDN($dn);

            $issuer = new X509;
            $issuer->setPrivateKey($key);
            $issuer->setDN($dn);

            $authority = new X509;
            // The validity starts in the past to tolerate clock skew between the two peers.
            $authority->setStartDate('-1 day');
            $authority->setEndDate(self::VALIDITY);
            $authority->setSerialNumber((string) random_int(1, PHP_INT_MAX), 10);

            /** @var array<array-key, mixed>|false $signed */
            $signed = $authority->sign($issuer, $subject);
            if ($signed === false) {
                throw new RTCCertificateException('Could not sign the generated certificate!');
            }
            $this->certificate = $authority->saveX509($signed);
            $this->der = self::toDer($this->certificate);
            $this->expires = self::parseExpiry($signed);
        } catch (RTCCertificateException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new RTCCertificateException('Could not generate a certificate: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Strip the PEM armour of a certificate, yielding its DER encoding.
     */
    private static function toDer(string $pem): string
    {
        $body = preg_replace('#-----(BEGIN|END) CERTIFICATE-----|\s#', '', $pem);
        $der = base64_decode((string) $body, true);
        if ($der === false) {
            throw new RTCCertificateException('The certificate is not valid PEM!');
        }
        return $der;
    }

    /**
     * Read the notAfter date out of a parsed certificate.
     */
    private static function parseExpiry(array $certificate): DateTimeImmutable
    {
        /** @var array<string, mixed> $tbs */
        $tbs = $certificate['tbsCertificate'] ?? [];
        /** @var array<string, mixed> $validity */
        $validity = $tbs['validity'] ?? [];
        /** @var array{utcTime?: string, generalTime?: string} $notAfter */
        $notAfter = $validity['notAfter'] ?? [];
        $date = $notAfter['utcTime'] ?? $notAfter['generalTime'] ?? null;
        try {
            return $date !== null ? new DateTimeImmutable($date) : new DateTimeImmutable(self::VALIDITY);
        } catch (Throwable) {
            return new DateTimeImmutable(self::VALIDITY);
        }
    }

    /**
     * Gets the certificate, in PEM form.
     */
    public function getCertificate(): string
    {
        return $this->certificate;
    }

    /**
     * Gets the DER encoding of the certificate, as sent in the DTLS Certificate message.
     */
    public function getDer(): string
    {
        return $this->der;
    }

    /**
     * Gets the private key.
     */
    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }
}
