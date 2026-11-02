<?php

namespace Tests\Webrtc\DTLS;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Webrtc\DTLS\DTLS\Handshake;
use Webrtc\DTLS\DTLS\RecordLayer;

/**
 * The anti-replay window of the record layer (RFC 6347 section 4.1.2.6): replays are dropped, records
 * reordered within the window are accepted, and its state stays the same size however long the
 * connection lasts.
 */
#[CoversClass(RecordLayer::class)]
#[CoversClass(Handshake::class)]
class RecordLayerTest extends TestCase
{
    private RecordLayer $sender;
    private RecordLayer $receiver;

    protected function setUp(): void
    {
        [$keyA, $saltA, $keyB, $saltB] = [random_bytes(16), random_bytes(4), random_bytes(16), random_bytes(4)];
        $this->sender = new RecordLayer();
        $this->sender->setKeys($keyA, $saltA, $keyB, $saltB);
        $this->sender->activateWrite();
        $this->receiver = new RecordLayer();
        $this->receiver->setKeys($keyB, $saltB, $keyA, $saltA);
        $this->receiver->activateRead();
    }

    /** @return list<string> The payloads of the records of the datagram the receiver accepted. */
    private function receive(string $datagram): array
    {
        return array_column($this->receiver->decode($datagram), 'payload');
    }

    private function record(string $payload): string
    {
        return $this->sender->encode(RecordLayer::TYPE_APPLICATION_DATA, $payload);
    }

    public function testReplaysAreDropped(): void
    {
        $first = $this->record('first');
        $second = $this->record('second');
        $this->assertSame(['first'], $this->receive($first));
        $this->assertSame(['second'], $this->receive($second));
        $this->assertSame([], $this->receive($first));
        $this->assertSame([], $this->receive($second));
    }

    public function testRecordsReorderedWithinTheWindowAreAccepted(): void
    {
        $records = [];
        for ($i = 0; $i < RecordLayer::REPLAY_WINDOW; $i++) {
            $records[] = $this->record("r$i");
        }
        // The newest first, then the others, oldest first: all within the window.
        $this->assertSame(['r'.(RecordLayer::REPLAY_WINDOW - 1)], $this->receive(array_pop($records)));
        foreach ($records as $i => $record) {
            $this->assertSame(["r$i"], $this->receive($record));
        }
        foreach ($records as $record) {
            $this->assertSame([], $this->receive($record));
        }
    }

    public function testRecordsOlderThanTheWindowAreDropped(): void
    {
        $old = $this->record('old');
        for ($i = 0; $i < RecordLayer::REPLAY_WINDOW; $i++) {
            $this->record('skipped');
        }
        $this->assertSame(['new'], $this->receive($this->record('new')));
        $this->assertSame([], $this->receive($old));
    }

    public function testForgedRecordsDoNotMoveTheWindow(): void
    {
        $genuine = $this->record('genuine');
        // A record far ahead, that fails authentication.
        $forged = $this->record('forged');
        $forged = substr_replace($forged, substr(pack('J', 1_000_000), 2), 5, 6);
        $this->assertSame([], $this->receive($forged));
        $this->assertSame(['genuine'], $this->receive($genuine));
    }

    /**
     * Unauthenticated (epoch 0) records can be spoofed by anyone who can send from the peer's
     * address: one with a huge sequence number must not make the genuine handshake records look
     * too old, nor can many of them grow the receiver's state.
     */
    public function testSpoofedPlaintextRecordsDoNotBlockTheHandshake(): void
    {
        $peer = new RecordLayer();
        $receiver = new RecordLayer();
        $genuine = [];
        for ($i = 0; $i < 3; $i++) {
            $genuine[] = $peer->encode(RecordLayer::TYPE_HANDSHAKE, "flight $i");
        }
        $spoofer = new RecordLayer();
        $spoofed = $spoofer->encode(RecordLayer::TYPE_HANDSHAKE, 'spoofed');
        $receive = static fn (string $datagram): array => array_column($receiver->decode($datagram), 'payload');

        $this->assertSame(['spoofed'], $receive(substr_replace($spoofed, substr(pack('J', 1 << 40), 2), 5, 6)));
        $this->assertSame(['flight 1'], $receive($genuine[1]));
        $this->assertSame(['flight 0'], $receive($genuine[0]));
        $this->assertSame([], $receive($genuine[0]));
        $this->assertSame(['flight 2'], $receive($genuine[2]));

        $size = \strlen(serialize($receiver));
        for ($i = 0; $i < 1000; $i++) {
            $receive(substr_replace($spoofed, substr(pack('J', (1 << 41) + $i), 2), 5, 6));
        }
        $this->assertLessThan($size + 64 * 32, \strlen(serialize($receiver)));
    }

    /**
     * The receiver used to remember every sequence number it accepted: the state of a long-lived
     * connection (and the session it's saved in) grew with each record it ever received.
     */
    public function testTheReplayStateDoesNotGrowWithTheRecordsReceived(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $this->receive($this->record("r$i"));
        }
        $size = \strlen(serialize($this->receiver));
        $memory = memory_get_usage();
        for ($i = 0; $i < 20_000; $i++) {
            $this->assertSame(['x'], $this->receive($this->record('x')));
        }
        $this->assertLessThan(1024, memory_get_usage() - $memory);
        // The sequence numbers serialize with more digits, nothing else.
        $this->assertLessThanOrEqual($size + 4, \strlen(serialize($this->receiver)));
    }
}
