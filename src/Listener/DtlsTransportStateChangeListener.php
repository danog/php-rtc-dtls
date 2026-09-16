<?php

namespace Webrtc\DTLS\Listener;

/**
 * Notified when an {@see \Webrtc\DTLS\DTLS\RTCDtlsTransport} changes state.
 *
 * Typed replacement for the former Evenement "statechange" event (which carried no payload). The
 * listener is a plain object captured verbatim by a serialize cycle.
 */
interface DtlsTransportStateChangeListener
{
    public function onDtlsTransportStateChange(): void;
}
