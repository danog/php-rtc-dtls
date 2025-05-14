<?php

namespace Tests\Webrtc\DTLS;

use Webrtc\DataChannel\RTCDataChannel;
use Webrtc\DataChannel\RTCSctpTransportInterface;

class Receiver implements RTCSctpTransportInterface
{
    public function __construct(private bool $broken = false)
    {
    }

    private array $data = []
    ;
    public function onReceived(string $data): void
    {
        if ($this->broken) {
            return;
        }
        $this->data []= $data;
    }

    public function onErrorOrClosed(): void
    {
        // TODO: Implement onErrorOrClosed() method.
    }

    public function getData(): array
    {
        return $this->data;
    }

    public function dataChannelOpen(RTCDataChannel $channel): void
    {
        // TODO: Implement dataChannelOpen() method.
    }

    public function dataChannelAddNegotiated(RTCDataChannel $channel): void
    {
        // TODO: Implement dataChannelAddNegotiated() method.
    }

    public function dataChannelClose(RTCDataChannel $channel): void
    {
        // TODO: Implement dataChannelClose() method.
    }
}