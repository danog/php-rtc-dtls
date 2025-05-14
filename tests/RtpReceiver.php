<?php

namespace Tests\Webrtc\DTLS;

use Webrtc\RTCP\RtcpPacketInterface;
use Webrtc\RTP\Receiver\RtpReceiverInterface;
use Webrtc\RTP\RtpPacket;

class RtpReceiver implements RtpReceiverInterface
{
    private array $rtpPackets = [];
    private array $rtcpPackets = [];

    public function handleRtcpPacket(RtcpPacketInterface $packet): void
    {
        $this->rtcpPackets[] = $packet;
    }

    public function handleRtpPacket(RtpPacket $packet, int $arrivalTimeMs): void
    {
        $this->rtpPackets[] = $packet;
    }

    public function getRtpPackets(): array
    {
        return $this->rtpPackets;
    }

    public function getRtcpPackets(): array
    {
        return $this->rtcpPackets;
    }

    public function stop(): void
    {
    }
}