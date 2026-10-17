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

use OpenSSLAsymmetricKey;
use phpseclib4\Crypt\DH;
use phpseclib4\Crypt\EC;
use Webrtc\DTLS\Exception\SSLException;

/**
 * An EC private key: the certificate's, or an ephemeral ECDHE one.
 *
 * Backed by OpenSSL, or by phpseclib if the extension isn't loaded (or fails, e.g. without an
 * openssl.cnf on Windows): see {@see Crypto::useOpenssl()}.
 *
 * @internal
 */
final class EcPrivateKey
{
    /** The SubjectPublicKeyInfo of a P-256 point, up to the uncompressed point itself. */
    private const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

    private function __construct(private readonly OpenSSLAsymmetricKey|EC\PrivateKey $key)
    {
    }

    /**
     * Generate a P-256 key.
     */
    public static function generateP256(): self
    {
        if (Crypto::useOpenssl()) {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            if ($key !== false) {
                return new self($key);
            }
        }
        return new self(EC::createKey('secp256r1'));
    }

    /**
     * Load a PEM-encoded EC private key.
     *
     * @throws SSLException If it isn't an EC private key.
     */
    public static function load(string $pem): self
    {
        if (Crypto::useOpenssl()) {
            $key = openssl_pkey_get_private($pem);
            if ($key !== false) {
                if ((openssl_pkey_get_details($key)['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
                    throw new SSLException('The provided key is not an EC private key!');
                }
                return new self($key);
            }
        }
        $key = EC::loadPrivateKey($pem);
        if (!$key instanceof EC\PrivateKey) {
            throw new SSLException('The provided key is not an EC private key!');
        }
        return new self($key);
    }

    /**
     * The public point, uncompressed (0x04 || x || y).
     */
    public function getPoint(): string
    {
        if ($this->key instanceof EC\PrivateKey) {
            /** @var string */
            return $this->key->getPublicKey()->getEncodedCoordinates();
        }
        $details = openssl_pkey_get_details($this->key);
        if ($details === false || !isset($details['ec']['x'], $details['ec']['y'], $details['bits'])) {
            throw new SSLException('Could not get the EC public key!');
        }
        $length = intdiv((int) $details['bits'] + 7, 8);
        return "\x04".str_pad((string) $details['ec']['x'], $length, "\0", STR_PAD_LEFT)
            .str_pad((string) $details['ec']['y'], $length, "\0", STR_PAD_LEFT);
    }

    /**
     * The ECDH shared secret (the x coordinate) with an uncompressed P-256 point.
     *
     * @throws SSLException If the point is invalid.
     */
    public function computeSharedSecret(string $peerPoint): string
    {
        $spki = (string) hex2bin(self::P256_SPKI_PREFIX).$peerPoint;
        if ($this->key instanceof EC\PrivateKey) {
            $peerKey = EC::loadPublicKey($spki);
            \assert($peerKey instanceof EC\PublicKey);
            /** @var string */
            return DH::computeSecret($this->key, $peerKey->getEncodedCoordinates());
        }
        // Loading the point checks that it is on the curve.
        $peerKey = openssl_pkey_get_public(Crypto::pem('PUBLIC KEY', $spki));
        $secret = $peerKey === false ? false : openssl_pkey_derive($peerKey, $this->key);
        if ($secret === false) {
            throw new SSLException('Invalid ECDHE public key!');
        }
        return $secret;
    }

    /**
     * Sign with ECDSA and SHA-256, returning the DER-encoded signature.
     */
    public function sign(string $data): string
    {
        if ($this->key instanceof EC\PrivateKey) {
            /** @var string */
            return $this->key->withSignatureFormat('ASN1')->withHash('sha256')->sign($data);
        }
        if (!openssl_sign($data, $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new SSLException('Could not sign: '.(openssl_error_string() ?: 'unknown error'));
        }
        /** @var string $signature */
        return $signature;
    }

    /**
     * The key in PEM form.
     */
    public function toPem(): string
    {
        if ($this->key instanceof EC\PrivateKey) {
            return $this->key->toString('PKCS8');
        }
        if (!openssl_pkey_export($this->key, $pem)) {
            throw new SSLException('Could not export the private key: '.(openssl_error_string() ?: 'unknown error'));
        }
        /** @var string $pem */
        return $pem;
    }

    /**
     * The phpseclib key.
     */
    public function toPhpseclib(): EC\PrivateKey
    {
        if ($this->key instanceof EC\PrivateKey) {
            return $this->key;
        }
        $key = EC::loadPrivateKey($this->toPem());
        \assert($key instanceof EC\PrivateKey);
        return $key;
    }

    /**
     * The OpenSSL key, if backed by OpenSSL.
     */
    public function getOpenssl(): ?OpenSSLAsymmetricKey
    {
        return $this->key instanceof OpenSSLAsymmetricKey ? $this->key : null;
    }
}
