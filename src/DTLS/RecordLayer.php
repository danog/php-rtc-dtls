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

use Webrtc\DTLS\Exception\SSLException;
use phpseclib3\Crypt\AES;
use Throwable;

/**
 * The DTLS 1.2 record layer (RFC 6347 section 4.1).
 *
 * A DTLS record adds an explicit 16-bit epoch and a 48-bit sequence number to the TLS record
 * header, because datagrams may be lost or reordered. Records are protected with an AEAD cipher
 * (RFC 5288), whose nonce is the four byte implicit salt from the key block followed by an eight
 * byte explicit part carried in the record itself.
 */
final class RecordLayer
{
    public const TYPE_CHANGE_CIPHER_SPEC = 20;
    public const TYPE_ALERT = 21;
    public const TYPE_HANDSHAKE = 22;
    public const TYPE_APPLICATION_DATA = 23;

    /** DTLS 1.2 is encoded as {254, 253}, i.e. the ones' complement of 1.2. */
    public const VERSION_1_2 = "\xFE\xFD";
    /** DTLS 1.0 is used in the first ClientHello for backwards compatibility. */
    public const VERSION_1_0 = "\xFE\xFF";

    private const HEADER_LENGTH = 13;
    private const EXPLICIT_NONCE_LENGTH = 8;
    private const TAG_LENGTH = 16;

    /** Outgoing epoch, incremented by each ChangeCipherSpec we send. */
    private int $writeEpoch = 0;
    /**
     * Next outgoing record sequence number, per epoch.
     *
     * Kept per epoch rather than as a single counter because a retransmitted flight has to be
     * re-encoded at the epoch it was originally sent in, while still taking a fresh sequence
     * number: peers drop a replayed number as a duplicate.
     *
     * @var array<int, int>
     */
    private array $writeSequences = [0 => 0];
    /** Incoming epoch, incremented by each ChangeCipherSpec we receive. */
    private int $readEpoch = 0;

    private ?string $writeKey = null;
    private ?string $writeSalt = null;
    private ?string $readKey = null;
    private ?string $readSalt = null;

    /** Highest sequence number accepted per epoch, for replay detection.
     *
     * @var array<int, array<int, true>>
     */
    private array $readSequences = [];

    /**
     * Mask applied to the record sequence to derive the explicit AEAD nonce.
     *
     * The nonce only has to be unique per key, and peers are free to choose it however they like:
     * OpenSSL picks a random one. Deriving ours from the sequence keeps it collision free while
     * still making it *different* from the sequence, so that any code confusing the two (the AEAD
     * additional data must use the sequence, never the nonce) fails loudly instead of silently
     * interoperating with itself.
     */
    private readonly string $explicitNonceMask;

    public function __construct()
    {
        $this->explicitNonceMask = random_bytes(8);
    }

    /**
     * Install the keys produced by the handshake, without activating them yet.
     */
    public function setKeys(string $writeKey, string $writeSalt, string $readKey, string $readSalt): void
    {
        $this->writeKey = $writeKey;
        $this->writeSalt = $writeSalt;
        $this->readKey = $readKey;
        $this->readSalt = $readSalt;
    }

    /**
     * Start protecting outgoing records, i.e. handle our own ChangeCipherSpec.
     */
    public function activateWrite(): void
    {
        $this->writeEpoch++;
        $this->writeSequences[$this->writeEpoch] ??= 0;
    }

    /**
     * Start expecting protected incoming records, i.e. handle the peer's ChangeCipherSpec.
     */
    public function activateRead(): void
    {
        $this->readEpoch++;
    }

    public function getWriteEpoch(): int
    {
        return $this->writeEpoch;
    }

    public function getReadEpoch(): int
    {
        return $this->readEpoch;
    }

    /**
     * Serialize one record, protecting it if the write epoch is already encrypted.
     */
    public function encode(int $type, string $payload, ?string $version = null, ?int $epoch = null): string
    {
        $version ??= self::VERSION_1_2;
        // A retransmission names the epoch its flight belongs to; everything else uses the
        // current one. Encrypted records are keyed per epoch, so re-encoding a pre-ChangeCipherSpec
        // record at the new epoch would make it undecryptable to the peer.
        $epoch ??= $this->writeEpoch;
        $sequence = $this->writeSequences[$epoch] ?? 0;
        $this->writeSequences[$epoch] = $sequence + 1;

        if ($epoch === 0 || $this->writeKey === null) {
            return \chr($type).$version.self::sequence($epoch, $sequence)
                .pack('n', \strlen($payload)).$payload;
        }

        // The explicit nonce only has to be unique per key; peers are free to use a random one,
        // so it must never be confused with the record's sequence number.
        $explicit = self::sequence($epoch, $sequence) ^ $this->explicitNonceMask;
        \assert($this->writeSalt !== null);
        $nonce = $this->writeSalt.$explicit;
        // RFC 5246 section 6.2.3.3: the additional data is built from the record's own epoch and
        // sequence number, not from the explicit nonce carried in the payload.
        $aad = self::sequence($epoch, $sequence).\chr($type).$version.pack('n', \strlen($payload));

        $aes = new AES('gcm');
        $aes->setKey($this->writeKey);
        $aes->setNonce($nonce);
        $aes->setAAD($aad);
        $ciphertext = $aes->encrypt($payload).$aes->getTag();

        $body = $explicit.$ciphertext;
        return \chr($type).$version.self::sequence($epoch, $sequence)
            .pack('n', \strlen($body)).$body;
    }

    /**
     * Split a datagram into records and decrypt the ones belonging to the current read epoch.
     *
     * Records from an unexpected epoch, replays and records that fail authentication are dropped
     * rather than reported, as required by RFC 6347 section 4.1.2.1.
     *
     * @return list<array{type: int, payload: string, epoch: int}>
     */
    public function decode(string $datagram): array
    {
        $records = [];
        $offset = 0;
        $total = \strlen($datagram);

        while ($offset + self::HEADER_LENGTH <= $total) {
            $type = \ord($datagram[$offset]);
            $version = substr($datagram, $offset + 1, 2);
            $epoch = Handshake::uint16(substr($datagram, $offset + 3, 2));
            $sequence = self::parseSequence(substr($datagram, $offset + 5, 6));
            $length = Handshake::uint16(substr($datagram, $offset + 11, 2));
            $offset += self::HEADER_LENGTH;

            if ($offset + $length > $total) {
                // Truncated record: the rest of the datagram is unusable.
                break;
            }
            $body = substr($datagram, $offset, $length);
            $offset += $length;

            if ($epoch !== $this->readEpoch) {
                // Either a retransmission from a previous epoch or an early record from the next
                // one; both are safe to ignore, the peer will retransmit if it matters.
                continue;
            }
            if (isset($this->readSequences[$epoch][$sequence])) {
                continue;
            }
            $this->readSequences[$epoch][$sequence] = true;

            if ($epoch === 0 || $this->readKey === null) {
                $records[] = ['type' => $type, 'payload' => $body, 'epoch' => $epoch];
                if ($type === self::TYPE_CHANGE_CIPHER_SPEC) {
                    // The epoch has to advance right here: peers routinely put ChangeCipherSpec
                    // and the encrypted Finished in the *same* datagram, and the records that
                    // follow in this very buffer already belong to the new epoch.
                    $this->activateRead();
                }
                continue;
            }

            if ($length < self::EXPLICIT_NONCE_LENGTH + self::TAG_LENGTH) {
                continue;
            }
            $explicit = substr($body, 0, self::EXPLICIT_NONCE_LENGTH);
            $ciphertext = substr($body, self::EXPLICIT_NONCE_LENGTH, -self::TAG_LENGTH);
            $tag = substr($body, -self::TAG_LENGTH);

            $aad = self::sequence($epoch, $sequence).\chr($type).$version.pack('n', \strlen($ciphertext));

            try {
                $aes = new AES('gcm');
                $aes->setKey($this->readKey);
                \assert($this->readSalt !== null);
                $aes->setNonce($this->readSalt.$explicit);
                $aes->setAAD($aad);
                $aes->setTag($tag);
                $plaintext = $aes->decrypt($ciphertext);
            } catch (Throwable) {
                // A forged or corrupted record; silently discard it.
                continue;
            }

            $records[] = ['type' => $type, 'payload' => $plaintext, 'epoch' => $epoch];
        }

        return $records;
    }

    /**
     * Encode a 16-bit epoch followed by a 48-bit sequence number.
     */
    private static function sequence(int $epoch, int $sequence): string
    {
        return pack('n', $epoch).substr(pack('J', $sequence), 2);
    }

    /**
     * Decode a 48-bit sequence number.
     */
    private static function parseSequence(string $raw): int
    {
        $value = unpack('J', "\0\0".$raw);
        return $value === false ? 0 : (int) $value[1];
    }

    /**
     * @throws SSLException Always; used to report a fatal protocol violation.
     */
    public static function fail(string $message): never
    {
        throw new SSLException($message);
    }
}
