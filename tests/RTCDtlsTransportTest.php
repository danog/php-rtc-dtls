<?php

namespace Tests\Webrtc\DTLS;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\DTLS\DTLS\Exception\TLSException;
use Webrtc\DTLS\DTLS\RTCCertificate;
use Webrtc\DTLS\DTLS\RTCDtlsTransport;
use Webrtc\DTLS\DTLS\Srtp;
use Webrtc\DTLS\DTLS\TLS\Handshake;
use Webrtc\DTLS\DTLS\TLS\TLS;
use Webrtc\ICE\Enum\IceRole;
use Webrtc\RTPParameter\RTCRtpCodecParameters;
use Webrtc\RTPParameter\RTCRtpDecodingParameters;
use Webrtc\RTPParameter\RTCRtpReceiveParameters;
use Webrtc\SDP\DtlsParameter\RTCDtlsFingerprint;
use Webrtc\DTLS\Exception\OpenSSLException;
use Webrtc\Stats\enum\TLSState;
use Amp\CancelledException;
use Amp\TimeoutCancellation;
use function Amp\async;

#[UsesClass(RTCCertificate::class)]
#[UsesClass(Srtp::class)]
#[UsesClass(Handshake::class)]
#[UsesClass(TLS::class)]
#[CoversClass(RTCDtlsTransport::class)]
class RTCDtlsTransportTest extends TestCase
{
    /** How long a handshake may take before the test gives up on it. */
    private const HANDSHAKE_TIMEOUT = 30;

    private ?DropList $drops = null;
    private bool $disconnect = false;

    public function testData()
    {
        [$serverReceiver, $clientReceiver] = [new Receiver(), new Receiver()];
        [$server, $client] = $this->createDtlsTransport();
        $client->setSctpReceiver($clientReceiver);
        $server->setSctpReceiver($serverReceiver);

        $this->connect($server, $client);

        // Send encrypted data
        $server->sendData("Hello");
        $this->assertEquals("Hello", rtrim($clientReceiver->getData()[0], "\0"));

        $client->sendData("Bye");
        $this->assertEquals("Bye", rtrim($serverReceiver->getData()[0], "\0"));

        // Shutdown
        $server->stop();
        $this->assertEquals(TLSState::CLOSED, $server->getState());
        $this->assertEquals(TLSState::CLOSED, $client->getState());

        // Try closing again
        $server->stop();
        $client->stop();

        // Try sending after close
        $this->expectException(TLSException::class);
        $server->sendData("Hi!");
    }

    public function testDataHandlerError()
    {
        [$serverReceiver, $clientReceiver] = [new Receiver(), new Receiver(true)];
        [$server, $client] = $this->createDtlsTransport();
        $client->setSctpReceiver($clientReceiver);
        $server->setSctpReceiver($serverReceiver);

        $this->connect($server, $client);

        // Send encrypted data
        $server->sendData("Hello");

        // Shutdown
        $server->stop();
        $client->stop();
        $this->assertTrue(true); // No exception means success test
    }

    public function testRtp()
    {
        [$serverRtpReceiver, $clientRtpReceiver] = [new RtpReceiver(), new RtpReceiver()];
        [$server, $client] = $this->createDtlsTransport();

        $server->setRtpReceiver($serverRtpReceiver, $this->getRtpReceiverParameters(1831097322));
        $client->setRtpReceiver($clientRtpReceiver, $this->getRtpReceiverParameters(4028317929));

        $this->connect($server, $client);

        $this->assertStat($server, $client, 0, 0);

        $rtpPacket = $this->getRtpPacket();
        $rtcpPacket = $this->getRtcpPacket();

        // Send RTP
        $server->sendRtp($rtpPacket);
        $this->assertStat($server, $client, 1, 0);
        $this->assertCount(0, $clientRtpReceiver->getRtcpPackets());
        $this->assertCount(1, $clientRtpReceiver->getRtpPackets());

        // Send RTCP
        $client->sendRtcp($rtcpPacket);
        $this->assertStat($server, $client, 1, 1);
        $this->assertCount(1, $serverRtpReceiver->getRtcpPackets());
        $this->assertCount(0, $serverRtpReceiver->getRtpPackets());

        // Shutdown
        $server->stop();
        // shutdown packet is delivered on peers
        $this->assertStat($server, $client, 2, 2);
        $this->assertEquals(TLSState::CLOSED, $server->getState());
        $this->assertEquals(TLSState::CLOSED, $client->getState());

        // Try closing again
        $server->stop();
        $client->stop();

        // Try sending after close
        // FIXME
//        $this->expectException(DTLSException::class);
//        $server->sendRtp($rtpPacket);
    }

    public function testRtpMalformed()
    {
        [$server, $client] = $this->createDtlsTransport();

        $rtpPacket = $this->getRtpPacket();
        $rtcpPacket = $this->getRtcpPacket();

        // Receive truncated RTP
        $server->handleRtpData(substr($rtpPacket, 0, 8), 0);

        // Receive truncated RTCP
        $server->handleRtcpData(substr($rtcpPacket, 0, 8));

        $this->assertTrue(true); // No exception means success test
    }

    public function testSrtpUnprotectError()
    {
        [$serverRtpReceiver, $clientRtpReceiver] = [new RtpReceiver(), new RtpReceiver()];
        [$server, $client] = $this->createDtlsTransport();

        $server->setRtpReceiver($serverRtpReceiver, $this->getRtpReceiverParameters(1831097322));
        $client->setRtpReceiver($clientRtpReceiver, $this->getRtpReceiverParameters(4028317929));

        $this->connect($server, $client);

        $this->assertStat($server, $client, 0, 0);

        $rtpPacket = $this->getRtpPacket();
        $rtcpPacket = $this->getRtcpPacket();

        // Send RTP
        $server->sendRtp($rtpPacket);

        // Send same RTP twice to trigger error
        $server->sendRtp($rtpPacket);
        $server->sendRtp($rtpPacket);
        $this->assertCount(0, $clientRtpReceiver->getRtcpPackets());
        $this->assertCount(1, $clientRtpReceiver->getRtpPackets());

        // Shutdown
        $server->stop();
        $client->stop();
    }

    public function testAbruptDisconnect()
    {
        [$server, $client] = $this->createDtlsTransport();

        $this->connect($server, $client);

        // Break connections
        $this->disconnect = true;

        // Close DTLS
        $server->stop();
        $client->stop();

        // Check the outcome
        $this->assertEquals(TLSState::CLOSED, $server->getState());
        $this->assertEquals(TLSState::CLOSED, $client->getState());
    }

    public function testAbruptDisconnect2()
    {
        [$clientIceTransport, $serverIceTransport] = $this->getIceTransportPairMock();
        [$clientCertificate, $serverCertificate] = [new RTCCertificate, new RTCCertificate];

        $client = new RTCDtlsTransport($clientIceTransport, $clientCertificate);
        $server = $this->getMockBuilder(RTCDtlsTransport::class)
            ->setConstructorArgs([$serverIceTransport, $serverCertificate])
            ->onlyMethods(['send'])
            ->getMock();

        $sendMock = function (string $data) {
            throw new \Exception("Not implemented");
        };
        $server->method('send')->willReturnCallback($sendMock);

        $this->connect($server, $client);

        // Close DTLS
        $server->stop();
        $client->stop();

        // Check the outcome
        $this->assertEquals(TLSState::CLOSED, $server->getState());
        $this->assertEquals(TLSState::CLOSED, $client->getState());
    }

    public function testBadClientFingerprint()
    {
        [$server, $client] = $this->createDtlsTransport();

        $wrongFingerprint = [new RTCDtlsFingerprint("wrong fingerprint", 'sha-256')];

        // Both ends must be handshaking at once, so each start() runs in its own fiber.
        $futures = [
            async(fn() => $server->start($wrongFingerprint)),
            async(fn() => $client->start($server->getPeerCertificates())),
        ];
        foreach ($futures as $future) {
            $future->await();
        }

        $this->assertEquals(TLSState::FAILED, $server->getState());
        $this->assertEquals(TLSState::CONNECTED, $client->getState());

        $server->stop();
        $client->stop();
    }

    public function testHandshakeErrorNoCommonSrtpProfile()
    {
        [$clientIceTransport, $serverIceTransport] = $this->getIceTransportPairMock();
        [$clientCertificate, $serverCertificate] = [new RTCCertificate, new RTCCertificate];

        $client = $this->getMockBuilder(RTCDtlsTransport::class)
            ->setConstructorArgs([$clientIceTransport, $clientCertificate])
            ->onlyMethods(['setupSrtp'])
            ->getMock();

        $setupSrtpClientMock = function () use ($client) {
            $srtp = new Srtp();

            $selectedProfile = Srtp::DEFAULT_PROFILES[0];
            $srtp->setProfile($selectedProfile);
            $srtpKeyMaterial = $client->getTls()->exportKeyingMaterial($selectedProfile["keyLength"], $selectedProfile["saltLent"]);

            $isServer = $client->getIceTransport()->getRole() === IceRole::Controlling;

            $client->setInboundSrtp($srtp->getInbound($srtpKeyMaterial, intval($isServer)));
            $client->setOutboundSrtp($srtp->getOutbound($srtpKeyMaterial, intval(!$isServer)));
        };
        $client->method('setupSrtp')->willReturnCallback($setupSrtpClientMock);

        $server = $this->getMockBuilder(RTCDtlsTransport::class)
            ->setConstructorArgs([$serverIceTransport, $serverCertificate])
            ->onlyMethods(['setupSrtp'])
            ->getMock();

        $setupSrtpSeverMock = function () use ($client) {
            $srtp = new Srtp();

            $selectedProfile = Srtp::DEFAULT_PROFILES[2];
            $srtp->setProfile($selectedProfile);
            $srtpKeyMaterial = $client->getTls()->exportKeyingMaterial($selectedProfile["keyLength"], $selectedProfile["saltLent"]);

            $isServer = $client->getIceTransport()->getRole() === IceRole::Controlling;

            $client->setInboundSrtp($srtp->getInbound($srtpKeyMaterial, intval($isServer)));
            $client->setOutboundSrtp($srtp->getOutbound($srtpKeyMaterial, intval(!$isServer)));
        };
        $server->method('setupSrtp')->willReturnCallback($setupSrtpSeverMock);

        $this->connect($server, $client);

        $this->assertEquals(TLSState::CONNECTED, $server->getState());
        $this->assertEquals(TLSState::CONNECTED, $client->getState());

        $server->stop();
        $client->stop();
    }

    /**
     * A lost flight has to be recovered by retransmission.
     *
     * The positions are fixed rather than random so that a failure is reproducible: a drop
     * rate makes the outcome differ run to run, which turns a regression into something that
     * looks like flakiness.
     */
    public function testRecoversFromALostFlight(): void
    {
        $this->drops = new DropList([1]);
        [$server, $client] = $this->createDtlsTransport();

        $this->connect($server, $client);

        $this->assertEquals(TLSState::CONNECTED, $server->getState());
        $this->assertEquals(TLSState::CONNECTED, $client->getState());

        $server->stop();
        $client->stop();
    }

    /**
     * Three consecutive losses take two doublings of the retransmission timer to get past,
     * so this also pins down that the backoff keeps running rather than giving up.
     */
    public function testRecoversFromSeveralLostFlights(): void
    {
        $this->drops = new DropList([1, 2, 3]);
        [$server, $client] = $this->createDtlsTransport();

        $this->connect($server, $client);

        $this->assertEquals(TLSState::CONNECTED, $server->getState());
        $this->assertEquals(TLSState::CONNECTED, $client->getState());

        $server->stop();
        $client->stop();
    }

    public function assertStat(RTCDtlsTransport $server, RTCDtlsTransport $client, int $packetsSentServer, int $packetsSentClient): void
    {
        $statsServer = $server->getStats()->getStats()["transport_" . spl_object_id($server)];
        $statsClient = $client->getStats()->getStats()["transport_" . spl_object_id($client)];

        $this->assertEquals($packetsSentServer, $statsServer->packetsSent);
        $this->assertEquals($packetsSentClient, $statsServer->packetsReceived);

        $this->assertGreaterThan(-1, $statsServer->bytesSent);
        $this->assertGreaterThan(-1, $statsServer->bytesReceived);

        $this->assertEquals($packetsSentClient, $statsClient->packetsSent);
        $this->assertEquals($packetsSentServer, $statsClient->packetsReceived);
        $this->assertGreaterThan(-1, $statsClient->bytesSent);
        $this->assertGreaterThan(-1, $statsClient->bytesReceived);

        $this->assertEquals($statsServer->bytesSent, $statsClient->bytesReceived);
        $this->assertEquals($statsClient->bytesSent, $statsServer->bytesReceived);
    }

    /**
     * @return array{RTCDtlsTransport, RTCDtlsTransport}
     * @throws OpenSSLException
     */
    private function createDtlsTransport(): array
    {
        [$clientIceTransport, $serverIceTransport] = $this->getIceTransportPairMock();
        [$clientCertificate, $serverCertificate] = [new RTCCertificate, new RTCCertificate];

        return [new RTCDtlsTransport($clientIceTransport, $clientCertificate), new RTCDtlsTransport($serverIceTransport, $serverCertificate)];
    }

    private function connectPairs(IceTransportMock $client, IceTransportMock $server): void
    {
        $drops = $this->drops ?? new DropList();

        $server->on('send', function ($data) use ($client, $drops) {
            if (!$drops->shouldDrop() && !$this->disconnect) {
                $client->emit("data", [$data]);
            }
        });
        $client->on('send', function ($data) use ($server, $drops) {
            if (!$drops->shouldDrop() && !$this->disconnect) {
                $server->emit("data", [$data]);
            }
        });
    }

    private function connect(RTCDtlsTransport $server, RTCDtlsTransport $client)
    {
        // Both ends must be handshaking at once, so each start() runs in its own fiber. The
        // wait is bounded: a handshake that never converges should fail the test rather than
        // hang it, which would take the rest of the suite down with it.
        $futures = [
            async(fn() => $server->start($client->getPeerCertificates())),
            async(fn() => $client->start($server->getPeerCertificates())),
        ];

        try {
            foreach ($futures as $future) {
                $future->await(new TimeoutCancellation(self::HANDSHAKE_TIMEOUT));
            }
        } catch (CancelledException) {
            self::fail(sprintf('The handshake did not complete within %s seconds.', self::HANDSHAKE_TIMEOUT));
        }
    }

    private function getRtpReceiverParameters(int $ssrc): RTCRtpReceiveParameters
    {
        return new RTCRtpReceiveParameters(
            codecs: [new RTCRtpCodecParameters('audio/PCMU', 8000, payloadType: 0),],
            encodings: [new RTCRtpDecodingParameters($ssrc, 0)]
        );
    }

    private function getRtpPacket()
    {
        return file_get_contents(__DIR__ . "/fixture/rtp.bin");
    }

    private function getRtcpPacket()
    {
        return file_get_contents(__DIR__ . "/fixture/rtcp_sr.bin");
    }

    private function getIceTransportPairMock()
    {
        $clientIceTransport = new IceTransportMock(IceRole::Controlling);
        $serverIceTransport = new IceTransportMock(IceRole::Controlled);

        $this->connectPairs($clientIceTransport, $serverIceTransport);

        return [$clientIceTransport, $serverIceTransport];
    }
}
