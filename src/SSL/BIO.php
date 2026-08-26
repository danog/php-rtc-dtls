<?php

/**
 * This file is part of the PHP WebRTC package, vendored and modified for MadelineProto.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\DTLS\SSL;

use Webrtc\DTLS\Enum\BioMethod;

/**
 * The datagram queues sitting between the DTLS engine and the network.
 *
 * Upstream this wrapped an OpenSSL memory BIO. It is now a plain pair of queues: {@see self::write()}
 * hands a datagram received from the ICE transport to the engine, and {@see self::read()} takes the
 * next datagram the engine wants to put on the wire.
 */
class BIO implements BIOInterface
{
    /** Datagrams received from the network, waiting to be fed to the engine. @var list<string> */
    private array $inbound = [];

    /** Datagrams produced by the engine, waiting to be sent. @var list<string> */
    private array $outbound = [];

    public function __construct(private readonly BioMethod $method = BioMethod::s_mem)
    {
    }

    /**
     * Take the next datagram the engine wants to send, or null if there is none.
     */
    public function read(): ?string
    {
        return array_shift($this->outbound);
    }

    /**
     * Total number of bytes queued for sending.
     */
    public function getPendingBytes(): int
    {
        $pending = 0;
        foreach ($this->outbound as $datagram) {
            $pending += \strlen($datagram);
        }
        return $pending;
    }

    /**
     * Queue a datagram received from the network.
     */
    public function write(string $buf): int
    {
        if ($buf !== '') {
            $this->inbound[] = $buf;
        }
        return \strlen($buf);
    }

    /**
     * Take the next datagram received from the network, for the engine to process.
     */
    public function takeInbound(): ?string
    {
        return array_shift($this->inbound);
    }

    /**
     * Queue a datagram produced by the engine.
     */
    public function pushOutbound(string $datagram): void
    {
        $this->outbound[] = $datagram;
    }

    public function hasOutbound(): bool
    {
        return $this->outbound !== [];
    }

    /**
     * Kept for interface compatibility: there is no native BIO to inspect any more.
     */
    public function handleBioErrors(mixed $bio): void
    {
    }

    public function getMethod(): BioMethod
    {
        return $this->method;
    }
}
