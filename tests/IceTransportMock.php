<?php

namespace Tests\Webrtc\DTLS;

use Evenement\EventEmitter;
use React\Promise\PromiseInterface;
use Webrtc\ICE\Enum\IceRole;
use Webrtc\ICE\RTCIceCandidate;
use Webrtc\ICE\RTCIceConnectionInterface;
use Webrtc\ICE\RTCIceGathererInterface;
use Webrtc\ICE\RTCIceParameters;
use Webrtc\ICE\RTCIceTransportInterface;

class IceTransportMock extends EventEmitter implements RTCIceTransportInterface
{
    public function __construct(private readonly IceRole $role)
    {
    }

    public function send(string $bytes)
    {
        $this->emit('send', [$bytes]);
    }

    public function getRole(): IceRole
    {
        return $this->role;
    }

    public function addRemoteCandidate(RTCIceCandidate $candidate): void
    {
        // TODO: Implement addRemoteCandidate() method.
    }

    public function getIceGatherer(): RTCIceGathererInterface
    {
        // TODO: Implement getIceGatherer() method.
    }

    public function isRoleSet(): bool
    {
        // TODO: Implement isRoleSet() method.
    }

    public function setRoleSet(bool $roleSet): void
    {
        // TODO: Implement setRoleSet() method.
    }

    public function getIceConnection(): RTCIceConnectionInterface
    {
        // TODO: Implement getIceConnection() method.
    }

    public function start(RTCIceParameters $remoteIceParameters): PromiseInterface
    {
        // TODO: Implement start() method.
    }

    public function stop(): void
    {
        // TODO: Implement stop() method.
    }
}