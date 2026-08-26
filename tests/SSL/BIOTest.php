<?php

namespace Tests\Webrtc\DTLS\SSL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Webrtc\DTLS\Enum\BioMethod;
use Webrtc\DTLS\SSL\BIO;

/**
 * The BIO is the boundary between the engine and the network.
 *
 * Datagram boundaries have to survive it: DTLS records are not a byte stream, and a BIO that
 * concatenated or split them would corrupt every handshake in a way that is hard to see from
 * further up. The old suite tested the OpenSSL BIO this class used to wrap, and asserted the
 * stream behaviour that is now exactly wrong.
 */
#[CoversClass(BIO::class)]
class BIOTest extends TestCase
{
    public function testKeepsInboundDatagramsSeparate(): void
    {
        $bio = new BIO(BioMethod::s_mem);
        $bio->write('first');
        $bio->write('second');

        $this->assertSame('first', $bio->takeInbound());
        $this->assertSame('second', $bio->takeInbound());
        $this->assertNull($bio->takeInbound(), 'the queue must drain rather than repeat');
    }

    public function testKeepsOutboundDatagramsSeparate(): void
    {
        $bio = new BIO(BioMethod::s_mem);
        $bio->pushOutbound('first');
        $bio->pushOutbound('second');

        $this->assertSame('first', $bio->read());
        $this->assertSame('second', $bio->read());
        $this->assertNull($bio->read());
    }

    public function testReadReturnsNullWhenNothingIsQueued(): void
    {
        $this->assertNull((new BIO(BioMethod::s_mem))->read());
    }

    public function testInboundAndOutboundDoNotShareAQueue(): void
    {
        $bio = new BIO(BioMethod::s_mem);
        $bio->write('from the network');
        $bio->pushOutbound('to the network');

        $this->assertSame('to the network', $bio->read());
        $this->assertSame('from the network', $bio->takeInbound());
    }

    public function testReportsWhetherAnythingIsWaitingToBeSent(): void
    {
        $bio = new BIO(BioMethod::s_mem);
        $this->assertFalse($bio->hasOutbound());

        $bio->pushOutbound('datagram');
        $this->assertTrue($bio->hasOutbound());

        $bio->read();
        $this->assertFalse($bio->hasOutbound());
    }

    public function testCountsBytesWaitingToBeSent(): void
    {
        $bio = new BIO(BioMethod::s_mem);
        $this->assertSame(0, $bio->getPendingBytes());

        $bio->pushOutbound('12345');
        $bio->pushOutbound('678');

        $this->assertSame(8, $bio->getPendingBytes());
    }

    /**
     * An empty write is not a datagram and must not become one, or the engine would be handed
     * a zero-length record to parse.
     */
    public function testIgnoresEmptyWrites(): void
    {
        $bio = new BIO(BioMethod::s_mem);
        $this->assertSame(0, $bio->write(''));
        $this->assertNull($bio->takeInbound());
    }

    public function testWriteReportsHowManyBytesItAccepted(): void
    {
        $this->assertSame(5, (new BIO(BioMethod::s_mem))->write('hello'));
    }

    public function testExposesItsMethod(): void
    {
        $this->assertSame(BioMethod::s_mem, (new BIO(BioMethod::s_mem))->getMethod());
    }
}
