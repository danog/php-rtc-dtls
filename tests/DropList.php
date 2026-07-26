<?php

namespace Tests\Webrtc\DTLS;

/**
 * Drops chosen datagrams from a stream, by position.
 *
 * Loss in these tests has to be reproducible. A random drop rate makes the outcome differ
 * run to run, which turns a real regression into something that looks like flakiness and
 * hides behind a rerun; picking the positions instead means a failure is always a failure.
 */
final class DropList
{
    private int $seen = 0;

    /**
     * @param list<int> $positions 1-based positions in the stream to drop.
     */
    public function __construct(private readonly array $positions = [])
    {
    }

    /**
     * Whether the next datagram should be dropped.
     */
    public function shouldDrop(): bool
    {
        return \in_array(++$this->seen, $this->positions, true);
    }
}
