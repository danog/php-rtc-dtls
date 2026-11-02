<?php

// Psalm stubs of the native classes of MadelineProto's madeline_crypto extension (0.5.0+): never loaded at runtime.

namespace danog\MadelineProto\Native;

final class Crypto
{
    public static function version(): string
    {
    }
}

final class AesGcm
{
    public function __construct(#[\SensitiveParameter] string $key)
    {
    }
    /** @return string The ciphertext followed by the 16-byte tag. */
    public function encrypt(string $nonce, string $aad, string $plaintext): string
    {
    }
    public function decrypt(string $nonce, string $aad, string $ciphertext, string $tag): string|false
    {
    }
}

final class AesCtr
{
    public function __construct(#[\SensitiveParameter] string $key, string $iv)
    {
    }
    public function process(string $data): string
    {
    }
    public static function once(#[\SensitiveParameter] string $key, string $iv, string $data): string
    {
    }
}

final class AesCtrKey
{
    public function __construct(#[\SensitiveParameter] string $key)
    {
    }
    public function apply(string $iv, string $data): string
    {
    }
}

final class Hmac
{
    /** @param 'md5'|'sha1'|'sha256'|'sha384'|'sha512' $algo */
    public function __construct(string $algo, #[\SensitiveParameter] string $key)
    {
    }
    public function mac(string $data): string
    {
    }
    /** @param 'md5'|'sha1'|'sha256'|'sha384'|'sha512' $algo */
    public static function compute(string $algo, #[\SensitiveParameter] string $key, string $data): string
    {
    }
}

final class Hash
{
    /** @param 'md5'|'sha1'|'sha256'|'sha384'|'sha512' $algo */
    public function __construct(string $algo)
    {
    }
    public function update(string $data): void
    {
    }
    public function final(): string
    {
    }
    /** @param 'md5'|'sha1'|'sha256'|'sha384'|'sha512' $algo */
    public static function digest(string $algo, string $data): string
    {
    }
}

final class Ec
{
    /** @return array{string, string} [PKCS#8 DER private key, SubjectPublicKeyInfo DER] */
    public static function generateP256(): array
    {
    }
    public static function derive(#[\SensitiveParameter] string $privateKey, string $peerSpki): string
    {
    }
    public static function sign(#[\SensitiveParameter] string $privateKey, string $data, string $hash): string
    {
    }
}

final class Signature
{
    public static function verify(string $publicKeyOrCertificate, string $data, string $signature, string $hash): bool
    {
    }
}

final class X509
{
    public static function selfSigned(#[\SensitiveParameter] string $privateKey, string $commonName, int $days, int $serial): string
    {
    }
    public static function publicKey(string $certificate): string
    {
    }
}
