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

/**
 * The TLS 1.2 pseudo-random function and the key schedule built on top of it.
 *
 * DTLS 1.2 shares its key schedule with TLS 1.2 (RFC 5246 section 5), so this covers the master
 * secret, the key block, the Finished verify data and the RFC 5705 exporter used to key SRTP.
 */
final class Prf
{
    /** Length of the master secret, in bytes. */
    public const MASTER_SECRET_LENGTH = 48;
    /** Length of the verify_data carried by a Finished message. */
    public const VERIFY_DATA_LENGTH = 12;

    /**
     * P_hash as defined in RFC 5246 section 5, using SHA-256.
     */
    public static function pHash(string $secret, string $seed, int $length, string $algo = 'sha256'): string
    {
        $result = '';
        $a = $seed;
        while (\strlen($result) < $length) {
            $a = hash_hmac($algo, $a, $secret, true);
            $result .= hash_hmac($algo, $a.$seed, $secret, true);
        }
        return substr($result, 0, $length);
    }

    /**
     * PRF(secret, label, seed) as defined in RFC 5246 section 5.
     */
    public static function prf(string $secret, string $label, string $seed, int $length, string $algo = 'sha256'): string
    {
        return self::pHash($secret, $label.$seed, $length, $algo);
    }

    /**
     * Derive the master secret from the pre-master secret and the two hello randoms.
     */
    public static function masterSecret(string $preMasterSecret, string $clientRandom, string $serverRandom): string
    {
        return self::prf(
            $preMasterSecret,
            'master secret',
            $clientRandom.$serverRandom,
            self::MASTER_SECRET_LENGTH
        );
    }

    /**
     * Derive the extended master secret of RFC 7627, which binds the handshake transcript.
     */
    public static function extendedMasterSecret(string $preMasterSecret, string $handshakeHash): string
    {
        return self::prf(
            $preMasterSecret,
            'extended master secret',
            $handshakeHash,
            self::MASTER_SECRET_LENGTH
        );
    }

    /**
     * Expand the master secret into the per-direction keys of an AEAD cipher suite.
     *
     * @return array{clientKey: string, serverKey: string, clientSalt: string, serverSalt: string}
     */
    public static function keyBlock(
        string $masterSecret,
        string $clientRandom,
        string $serverRandom,
        int $keyLength,
        int $saltLength
    ): array {
        // Note the inverted random order compared to the master secret computation.
        $block = self::prf(
            $masterSecret,
            'key expansion',
            $serverRandom.$clientRandom,
            2 * ($keyLength + $saltLength)
        );
        $offset = 0;
        $clientKey = substr($block, $offset, $keyLength);
        $offset += $keyLength;
        $serverKey = substr($block, $offset, $keyLength);
        $offset += $keyLength;
        $clientSalt = substr($block, $offset, $saltLength);
        $offset += $saltLength;
        $serverSalt = substr($block, $offset, $saltLength);

        return [
            'clientKey' => $clientKey,
            'serverKey' => $serverKey,
            'clientSalt' => $clientSalt,
            'serverSalt' => $serverSalt,
        ];
    }

    /**
     * Compute the verify_data of a Finished message.
     *
     * @param bool $client Whether the Finished is the one sent by the client.
     */
    public static function verifyData(string $masterSecret, string $handshakeHash, bool $client): string
    {
        return self::prf(
            $masterSecret,
            $client ? 'client finished' : 'server finished',
            $handshakeHash,
            self::VERIFY_DATA_LENGTH
        );
    }

    /**
     * Export keying material as defined in RFC 5705, used to key SRTP (RFC 5764).
     */
    public static function exportKeyingMaterial(
        string $masterSecret,
        string $label,
        string $clientRandom,
        string $serverRandom,
        int $length,
        ?string $context = null
    ): string {
        $seed = $clientRandom.$serverRandom;
        if ($context !== null) {
            $seed .= pack('n', \strlen($context)).$context;
        }
        return self::prf($masterSecret, $label, $seed, $length);
    }
}
