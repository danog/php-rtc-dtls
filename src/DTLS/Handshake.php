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
 * Framing of DTLS handshake messages (RFC 6347 section 4.2.2).
 *
 * Handshake messages carry a message sequence number and may be split across several datagrams,
 * so this takes care of fragmenting outgoing messages to fit the path MTU and of reassembling
 * incoming ones. The handshake transcript, which both Finished messages authenticate, always uses
 * the *unfragmented* form of each message.
 */
final class Handshake
{
    public const HELLO_REQUEST = 0;
    public const CLIENT_HELLO = 1;
    public const SERVER_HELLO = 2;
    public const HELLO_VERIFY_REQUEST = 3;
    public const CERTIFICATE = 11;
    public const SERVER_KEY_EXCHANGE = 12;
    public const CERTIFICATE_REQUEST = 13;
    public const SERVER_HELLO_DONE = 14;
    public const CERTIFICATE_VERIFY = 15;
    public const CLIENT_KEY_EXCHANGE = 16;
    public const FINISHED = 20;

    public const HEADER_LENGTH = 12;

    /**
     * Largest handshake fragment we emit, chosen to stay well inside a typical 1200 byte datagram
     * once the record and IP headers are accounted for.
     */
    private const MAX_FRAGMENT = 1000;

    /**
     * Partially received messages, keyed by message sequence number.
     *
     * @var array<int, array{type: int, length: int, buffer: string, received: array<int, int>}>
     */
    private array $pending = [];

    /** Next message sequence number we expect to deliver. */
    private int $nextExpected = 0;

    /**
     * Serialize a handshake message, splitting it into fragments if needed.
     *
     * @return list<string> The fragments, each ready to be placed in its own record.
     */
    public static function fragment(int $type, string $body, int $messageSeq): array
    {
        $length = \strlen($body);
        if ($length <= self::MAX_FRAGMENT) {
            return [self::header($type, $length, $messageSeq, 0, $length).$body];
        }

        $fragments = [];
        for ($offset = 0; $offset < $length; $offset += self::MAX_FRAGMENT) {
            $chunk = substr($body, $offset, self::MAX_FRAGMENT);
            $fragments[] = self::header($type, $length, $messageSeq, $offset, \strlen($chunk)).$chunk;
        }
        return $fragments;
    }

    /**
     * The 12 byte handshake header.
     */
    public static function header(int $type, int $length, int $messageSeq, int $offset, int $fragmentLength): string
    {
        return \chr($type)
            .substr(pack('N', $length), 1)
            .pack('n', $messageSeq)
            .substr(pack('N', $offset), 1)
            .substr(pack('N', $fragmentLength), 1);
    }

    /**
     * The form of a message that goes into the handshake transcript: a single, unfragmented copy.
     */
    public static function transcriptForm(int $type, string $body, int $messageSeq): string
    {
        return self::header($type, \strlen($body), $messageSeq, 0, \strlen($body)).$body;
    }

    /**
     * Feed one handshake record payload, which may hold several fragments.
     *
     * Messages are returned in sequence order; out of order fragments are buffered until the gap
     * before them is filled.
     *
     * @return list<array{type: int, body: string, seq: int}>
     */
    public function receive(string $payload): array
    {
        $offset = 0;
        $total = \strlen($payload);

        while ($offset + self::HEADER_LENGTH <= $total) {
            $type = \ord($payload[$offset]);
            $length = self::uint24(substr($payload, $offset + 1, 3));
            $messageSeq = unpack('n', substr($payload, $offset + 4, 2))[1];
            $fragmentOffset = self::uint24(substr($payload, $offset + 6, 3));
            $fragmentLength = self::uint24(substr($payload, $offset + 9, 3));
            $offset += self::HEADER_LENGTH;

            if ($offset + $fragmentLength > $total || $fragmentOffset + $fragmentLength > $length) {
                break;
            }
            $chunk = substr($payload, $offset, $fragmentLength);
            $offset += $fragmentLength;

            if ($messageSeq < $this->nextExpected) {
                // A retransmission of something we already processed.
                continue;
            }

            if (!isset($this->pending[$messageSeq])) {
                $this->pending[$messageSeq] = [
                    'type' => $type,
                    'length' => $length,
                    'buffer' => str_repeat("\0", $length),
                    'received' => [],
                ];
            }
            $entry = &$this->pending[$messageSeq];
            if ($fragmentLength > 0) {
                $entry['buffer'] = substr_replace($entry['buffer'], $chunk, $fragmentOffset, $fragmentLength);
            }
            $entry['received'][$fragmentOffset] = max(
                $entry['received'][$fragmentOffset] ?? 0,
                $fragmentLength
            );
            unset($entry);
        }

        return $this->drain();
    }

    /**
     * Emit every message that is complete and in order.
     *
     * @return list<array{type: int, body: string, seq: int}>
     */
    private function drain(): array
    {
        $ready = [];
        while (isset($this->pending[$this->nextExpected])) {
            $entry = $this->pending[$this->nextExpected];
            if (!self::isComplete($entry)) {
                break;
            }
            $ready[] = [
                'type' => $entry['type'],
                'body' => $entry['buffer'],
                'seq' => $this->nextExpected,
            ];
            unset($this->pending[$this->nextExpected]);
            $this->nextExpected++;
        }
        return $ready;
    }

    /**
     * Whether every byte of a message has been received.
     */
    private static function isComplete(array $entry): bool
    {
        if ($entry['length'] === 0) {
            return true;
        }
        $covered = 0;
        $offsets = $entry['received'];
        ksort($offsets);
        foreach ($offsets as $offset => $length) {
            if ($offset > $covered) {
                return false;
            }
            $covered = max($covered, $offset + $length);
        }
        return $covered >= $entry['length'];
    }

    /**
     * Decode a 24-bit big endian integer.
     */
    public static function uint24(string $raw): int
    {
        return unpack('N', "\0".$raw)[1];
    }

    /**
     * Encode a 24-bit big endian integer.
     */
    public static function packUint24(int $value): string
    {
        return substr(pack('N', $value), 1);
    }
}
