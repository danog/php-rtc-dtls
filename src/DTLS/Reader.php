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

/**
 * A cursor over a handshake message body.
 *
 * TLS structures are full of length-prefixed vectors; this keeps the parsing code readable and
 * makes every read bounds-checked, so a malformed message raises a clean error instead of
 * silently producing garbage.
 */
final class Reader
{
    private int $offset = 0;

    public function __construct(private readonly string $buffer)
    {
    }

    /**
     * @throws SSLException If fewer than `$length` bytes remain.
     */
    public function take(int $length): string
    {
        if ($this->offset + $length > \strlen($this->buffer)) {
            throw new SSLException('Truncated DTLS handshake message!');
        }
        $slice = substr($this->buffer, $this->offset, $length);
        $this->offset += $length;
        return $slice;
    }

    /**
     * @throws SSLException If fewer than `$length` bytes remain.
     */
    public function skip(int $length): void
    {
        $this->take($length);
    }

    /**
     * Read a vector with a one byte length prefix.
     *
     * @throws SSLException If the vector is truncated.
     */
    public function takeVector8(): string
    {
        return $this->take(\ord($this->take(1)));
    }

    /**
     * Read a vector with a two byte length prefix.
     *
     * @throws SSLException If the vector is truncated.
     */
    public function takeVector16(): string
    {
        return $this->take(Handshake::uint16($this->take(2)));
    }

    /**
     * Everything that has not been consumed yet.
     */
    public function rest(): string
    {
        return substr($this->buffer, $this->offset);
    }

    public function remaining(): int
    {
        return \strlen($this->buffer) - $this->offset;
    }
}
