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

use DateTimeImmutable;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\RSA;
use phpseclib4\File\X509;
use Throwable;
use Webrtc\DTLS\Exception\SSLException;

/**
 * The certificate cryptography of the handshake: OpenSSL, or phpseclib if the extension isn't loaded.
 *
 * @internal
 */
final class Crypto
{
    public const BACKEND_OPENSSL = 'openssl';
    public const BACKEND_PHPSECLIB = 'phpseclib';

    /**
     * The backend to use, instead of OpenSSL (if available): for tests.
     *
     * @var self::BACKEND_*|null
     */
    public static ?string $backend = null;

    /**
     * Whether to use OpenSSL.
     */
    public static function useOpenssl(): bool
    {
        return self::$backend !== self::BACKEND_PHPSECLIB && \extension_loaded('openssl');
    }

    /**
     * Wrap DER data in PEM armour.
     */
    public static function pem(string $label, string $der): string
    {
        return "-----BEGIN $label-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END $label-----\n";
    }

    /**
     * Verify a TLS 1.2 signature (ECDSA, or RSA with PKCS#1 v1.5) with the key of a DER-encoded certificate.
     *
     * @param 'sha1'|'sha224'|'sha256'|'sha384'|'sha512' $hash
     *
     * @throws SSLException If the certificate or the signature can't be parsed.
     */
    public static function verify(string $certificate, string $data, string $signature, string $hash): bool
    {
        if (self::useOpenssl()) {
            $publicKey = openssl_pkey_get_public(self::pem('CERTIFICATE', $certificate));
            if ($publicKey === false) {
                throw new SSLException('Could not load the peer certificate: '.(openssl_error_string() ?: 'unknown error'));
            }
            $result = openssl_verify($data, $signature, $publicKey, match ($hash) {
                'sha1' => OPENSSL_ALGO_SHA1,
                'sha224' => OPENSSL_ALGO_SHA224,
                'sha256' => OPENSSL_ALGO_SHA256,
                'sha384' => OPENSSL_ALGO_SHA384,
                'sha512' => OPENSSL_ALGO_SHA512,
            });
            if ($result === -1 || $result === false) {
                throw new SSLException('Could not verify the signature: '.(openssl_error_string() ?: 'unknown error'));
            }
            return $result === 1;
        }
        /** @var EC\PublicKey|RSA\PublicKey $publicKey */
        $publicKey = X509::load($certificate)->getPublicKey();
        /** @var EC\PublicKey|RSA\PublicKey $publicKey */
        $publicKey = $publicKey->withHash($hash);
        if ($publicKey instanceof RSA\PublicKey) {
            // TLS 1.2 rsa_pkcs1_* signatures use PKCS#1 v1.5, while phpseclib defaults to PSS.
            /** @var RSA\PublicKey $publicKey */
            $publicKey = $publicKey->withPadding(RSA::SIGNATURE_PKCS1);
        }
        if ($publicKey instanceof EC\PublicKey) {
            /** @var EC\PublicKey $publicKey */
            $publicKey = $publicKey->withSignatureFormat('ASN1');
        }
        /** @var bool */
        return $publicKey->verify($data, $signature);
    }

    /**
     * Create a self-signed certificate, valid for some days.
     *
     * WebRTC peers pin it by fingerprint, without checking its validity dates: with phpseclib it is valid
     * from a day ago anyway, to tolerate clock skew, OpenSSL can't set the start date.
     *
     * @param array{C: string, ST: string, L: string, O: string, CN: string} $dn
     *
     * @return string The certificate, in PEM form.
     */
    public static function selfSign(EcPrivateKey $key, array $dn, int $days): string
    {
        $openssl = $key->getOpenssl();
        if ($openssl !== null) {
            $csr = openssl_csr_new([
                'countryName' => $dn['C'],
                'stateOrProvinceName' => $dn['ST'],
                'localityName' => $dn['L'],
                'organizationName' => $dn['O'],
                'commonName' => $dn['CN'],
            ], $openssl, ['digest_alg' => 'sha256']);
            $certificate = \is_bool($csr) ? false : openssl_csr_sign($csr, null, $openssl, $days, ['digest_alg' => 'sha256'], random_int(1, PHP_INT_MAX));
            if ($certificate !== false && openssl_x509_export($certificate, $pem)) {
                /** @var string $pem */
                return $pem;
            }
            // Without an openssl.cnf, for example: use phpseclib.
        }
        $privateKey = $key->toPhpseclib();
        /** @var \phpseclib4\Crypt\Common\PublicKey $subjectPublicKey */
        $subjectPublicKey = $privateKey->getPublicKey();
        $certificate = new X509($subjectPublicKey);
        $certificate->setSubjectDN($dn);
        // The certificate is self-signed, so the issuer and the subject are identical.
        $certificate->setIssuerDN($dn);
        $certificate->setStartDate('-1 day');
        $certificate->setEndDate("+$days days");
        $certificate->setSerialNumber((string) random_int(1, PHP_INT_MAX), 10);
        // phpseclib 4 inverts signing: the private key signs the certificate in place.
        $privateKey->sign($certificate);
        return $certificate->toString();
    }

    /**
     * The notAfter date of a PEM-encoded certificate.
     *
     * @throws SSLException If it can't be parsed.
     */
    public static function getExpiry(string $certificate): DateTimeImmutable
    {
        if (self::useOpenssl()) {
            $parsed = openssl_x509_parse($certificate);
            if ($parsed === false || !isset($parsed['validTo_time_t'])) {
                throw new SSLException('Could not parse the certificate!');
            }
            return new DateTimeImmutable('@'.(int) $parsed['validTo_time_t']);
        }
        try {
            /** @var array<string, mixed> $tbs */
            $tbs = X509::load($certificate)->toArray()['tbsCertificate'] ?? [];
        } catch (Throwable $e) {
            throw new SSLException('Could not parse the certificate!', 0, $e);
        }
        // phpseclib 4 decodes the validity times into ASN.1 time objects that extend DateTime.
        /** @var array<string, mixed> $validity */
        $validity = $tbs['validity'] ?? [];
        /** @var array{utcTime?: \DateTimeInterface, generalTime?: \DateTimeInterface} $notAfter */
        $notAfter = $validity['notAfter'] ?? [];
        $date = $notAfter['generalTime'] ?? $notAfter['utcTime'] ?? null;
        if (!$date instanceof \DateTimeInterface) {
            throw new SSLException('The certificate has no expiry date!');
        }
        return DateTimeImmutable::createFromInterface($date);
    }
}
