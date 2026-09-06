<?php

namespace Tests\Webrtc\DTLS;

use Evenement\EventEmitter;
use Webrtc\ICE\Enum\IceRole;
use Webrtc\ICE\Listener\IceTransportDataListener;
use Webrtc\ICE\Listener\IceTransportDisconnectListener;
use Webrtc\ICE\RTCIceCandidate;
use Webrtc\ICE\RTCIceConnectionInterface;
use Webrtc\ICE\RTCIceGathererInterface;
use Webrtc\ICE\RTCIceParameters;
use Webrtc\ICE\RTCIceTransportInterface;

class IceTransportMock extends EventEmitter implements RTCIceTransportInterface
{
    /** @var list<IceTransportDataListener> */
    private array $dataListeners = [];

    /** @var list<IceTransportDisconnectListener> */
    private array $disconnectListeners = [];

    public function __construct(private readonly IceRole $role)
    {
    }

    public function addDataListener(IceTransportDataListener $listener): void
    {
        $this->dataListeners[] = $listener;
    }

    public function removeDataListener(IceTransportDataListener $listener): void
    {
        $this->dataListeners = array_values(array_filter(
            $this->dataListeners,
            static fn (IceTransportDataListener $existing): bool => $existing !== $listener
        ));
    }

    public function addDisconnectListener(IceTransportDisconnectListener $listener): void
    {
        $this->disconnectListeners[] = $listener;
    }

    /** Deliver a datagram to the registered data listeners (the DTLS transport and handshake). */
    public function deliver(string $data): void
    {
        foreach ($this->dataListeners as $listener) {
            $listener->onIceTransportData($data, 1);
        }
    }

    public function send(string $bytes): void
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

    public function start(RTCIceParameters $remoteIceParameters): void
    {
        // TODO: Implement start() method.
    }

    public function stop(): void
    {
        // TODO: Implement stop() method.
    }
}