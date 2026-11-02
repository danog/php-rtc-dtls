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

use danog\MadelineProto\Native\Ec as NativeEc;
use OpenSSLAsymmetricKey;
use phpseclib4\Crypt\DH;
use phpseclib4\Crypt\EC;
use Webrtc\DTLS\Exception\SSLException;

/**
 * An EC private key: the certificate's, or an ephemeral ECDHE one.
 *
 * Backed by madeline_crypto 0.5+ (the key is then its PKCS#8 DER encoding), by OpenSSL, or by phpseclib if
 * neither extension is loaded (or OpenSSL fails, e.g. without an openssl.cnf on Windows): see
 * {@see Crypto::useNative()} and {@see Crypto::useOpenssl()}.
 *
 * @internal
 */
final class EcPrivateKey
{
    /** The SubjectPublicKeyInfo of a P-256 point, up to the uncompressed point itself. */
    private const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

    /**
     * @param OpenSSLAsymmetricKey|EC\PrivateKey|string $key  The key; a string is the PKCS#8 DER encoding of a native key.
     * @param ?string                                   $spki The SubjectPublicKeyInfo of a native key, if known.
     */
    private function __construct(
        #[\SensitiveParameter] private readonly OpenSSLAsymmetricKey|EC\PrivateKey|string $key,
        private ?string $spki = null,
    ) {
    }

    /**
     * Generate a P-256 key.
     */
    public static function generateP256(): self
    {
        if (Crypto::useNative()) {
            [$key, $spki] = NativeEc::generateP256();
            return new self($key, $spki);
        }
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
    public static function load(#[\SensitiveParameter] string $pem): self
    {
        if (Crypto::useNative() && preg_match('#^\s*-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----\s*$#D', $pem, $matches)) {
            // PKCS#8, as exported by toPem() with any backend (a SEC 1 "EC PRIVATE KEY" is loaded by the others).
            $der = base64_decode((string) preg_replace('#\s#', '', $matches[1]), true);
            if ($der === false) {
                throw new SSLException('The provided key is not valid PEM!');
            }
            $key = new self($der);
            // Checks that it's a P-256 key, before it's used.
            try {
                $key->sign('');
            } catch (\Throwable $e) {
                throw new SSLException('The provided key is not a P-256 private key!', 0, $e);
            }
            return $key;
        }
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
        if (\is_string($this->key)) {
            // A loaded key's public key is computed by another backend: only certificate keys are loaded, and
            // they only sign.
            $this->spki ??= (string) hex2bin(self::P256_SPKI_PREFIX).$this->toPhpseclib()->getPublicKey()->getEncodedCoordinates();
            if (\strlen($this->spki) !== 91 || strncmp($this->spki, (string) hex2bin(self::P256_SPKI_PREFIX), 26) !== 0) {
                throw new SSLException('Could not get the EC public key!');
            }
            return substr($this->spki, 26);
        }
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
        if (\is_string($this->key)) {
            // Loading the point checks that it is on the curve.
            try {
                return NativeEc::derive($this->key, $spki);
            } catch (\Throwable $e) {
                throw new SSLException('Invalid ECDHE public key!', 0, $e);
            }
        }
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
        if (\is_string($this->key)) {
            return NativeEc::sign($this->key, $data, 'sha256');
        }
        if ($this->key instanceof EC\PrivateKey) {
            /** @var string */
            return $this->key->withSignatureFormat('ASN1')->withHash('sha256')->sign($data);
        }
        if (!openssl_sign($data, $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new SSLException('Could not sign: '.Crypto::opensslError());
        }
        /** @var string $signature */
        return $signature;
    }

    /**
     * The key in PEM form.
     */
    public function toPem(): string
    {
        if (\is_string($this->key)) {
            return Crypto::pem('PRIVATE KEY', $this->key);
        }
        if ($this->key instanceof EC\PrivateKey) {
            return $this->key->toString('PKCS8');
        }
        if (!openssl_pkey_export($this->key, $pem)) {
            throw new SSLException('Could not export the private key: '.Crypto::opensslError());
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
        // An unserialized key skips the initialization of the key formats of phpseclib, needed to load it.
        EC::getSupportedKeyFormats();
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

    /**
     * The PKCS#8 DER encoding of the key, if backed by madeline_crypto.
     */
    public function getNative(): ?string
    {
        return \is_string($this->key) ? $this->key : null;
    }

    /**
     * OpenSSL keys can't be serialized: the key is serialized in PEM form, and loaded back with whichever
     * backend is available then.
     *
     * @return array{pem: string, spki?: string}
     */
    public function __serialize(): array
    {
        return $this->spki === null ? ['pem' => $this->toPem()] : ['pem' => $this->toPem(), 'spki' => $this->spki];
    }

    /**
     * @param array<string, mixed> $data The PEM, or the phpseclib key itself, as serialized before 2.0.19 (only
     *     with phpseclib: OpenSSL keys couldn't be serialized)
     *
     * @throws SSLException If it isn't a serialized key.
     */
    public function __unserialize(array $data): void
    {
        if (isset($data['pem']) && \is_string($data['pem'])) {
            $loaded = self::load($data['pem']);
            $this->key = $loaded->key;
            $this->spki = \is_string($loaded->key) && isset($data['spki']) && \is_string($data['spki']) ? $data['spki'] : $loaded->spki;
            return;
        }
        $key = $data["\0".self::class."\0key"] ?? null;
        if (!$key instanceof EC\PrivateKey) {
            throw new SSLException('Invalid serialized EC private key!');
        }
        // An unserialized key skips the initialization of the key formats of phpseclib, needed to export it.
        EC::getSupportedKeyFormats();
        $loaded = self::load($key->toString('PKCS8'));
        $this->key = $loaded->key;
        $this->spki = $loaded->spki;
    }
}
