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

final class AesCbc
{
    public static function encrypt(#[\SensitiveParameter] string $key, string $iv, string $data): string
    {
    }
    public static function decrypt(#[\SensitiveParameter] string $key, string $iv, string $data): string
    {
    }
}

final class AesIge
{
    public static function encrypt(#[\SensitiveParameter] string $key, string $iv, string $data): string
    {
    }
    public static function decrypt(#[\SensitiveParameter] string $key, string $iv, string $data): string
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
