<?php

/**
 * This file is part of the PHP WebRTC package.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\DTLS\DTLS\TLS;

use Exception;
use Amp\DeferredFuture;
use Revolt\EventLoop;
use Throwable;
use Webrtc\DTLS\DTLS\Enum\SSLHandshakeState;
use Webrtc\DTLS\DTLS\Exception\HandshakeException;
use Webrtc\ICE\RTCIceTransportInterface;
use Webrtc\Mixin\EventForwarder;
use Webrtc\DTLS\Exception\OpenSSLException;
use Webrtc\DTLS\SSL\BIOInterface;
use Webrtc\DTLS\SSL\SSLInterface;
use Webrtc\Stats\enum\TLSState;

/**
 * Class Handshake
 *
 * Manages the DTLS (Datagram Transport Layer Security) handshake process using an asynchronous event loop.
 * This class handles both client and server-side handshake operations, managing timeouts, BIO buffer operations,
 * and state transitions during the TLS handshake process.
 *
 * @package Webrtc\DTLS\DTLS\TLS
 */
final class Handshake
{
    use EventForwarder;

    /** @var DeferredFuture Settled when the handshake finishes or fails */
    private DeferredFuture $deferred;

    /** @var SSLInterface The SSL context for the handshake */
    private SSLInterface $ssl;

    /** @var RTCIceTransportInterface The transport layer for sending/receiving data */
    private RTCIceTransportInterface $transport;

    /** @var BIOInterface The BIO buffer for SSL operations */
    private BIOInterface $bio;

    /** @var string|null Handle of the retransmission timer */
    private ?string $timer = null;

    /** @var bool Whether a handshake step is already queued on the event loop */
    private bool $advanceScheduled = false;

    /** @var array Listeners for transport events
     *
     * @var array<callable>
     */
    private array $listeners;

    /**
     * Handshake constructor.
     *
     * Initializes the handshake process with the given TLS context, transport, and initial state.
     *
     * @param TLS $tls The TLS context for this handshake
     * @param RTCIceTransportInterface $transport The transport layer for communication
     * @param SSLHandshakeState $state The initial handshake state (Accept or Connect)
     */
    public function __construct(private readonly TLS $tls, RTCIceTransportInterface $transport, private readonly SSLHandshakeState $state)
    {
        $this->deferred = new DeferredFuture();
        $this->transport = $transport;
        $this->ssl = $tls->getSsl();
        $this->bio = $tls->getBio();
        $this->setSSLHandshakeState();
        $this->listeners = $this->forwardEvents2Methods($this->transport, ['data' => 'receive']);
    }

    /**
     * Receives data from the transport and writes it to the BIO buffer.
     *
     * This method is called when data is received on the transport layer. It cancels any pending
     * timeout timer and writes the received data to the BIO buffer for SSL processing.
     *
     * @param string $bytes The received data bytes
     * @throws OpenSSLException If writing to the BIO buffer fails
     */
    private function receive(string $bytes): void
    {
        if ($this->timer !== null) {
            EventLoop::cancel($this->timer);
            $this->timer = null;
        }

        $this->bio->write($bytes);
        $this->scheduleAdvance();
    }

    /**
     * Initiates the handshake process.
     *
     * Blocks until the handshake completes, or throws if it fails.
     *
     * @return void
     * @throws HandshakeException If the handshake could not be completed.
     */
    public function do(): void
    {
        $this->scheduleAdvance();
        $this->deferred->getFuture()->await();
    }

    /**
     * Sets the SSL handshake state based on the constructor parameter.
     *
     * Configures the SSL context to either accept (server mode) or connect (client mode).
     */
    private function setSSLHandshakeState(): void
    {
        if ($this->state === SSLHandshakeState::Accept) {
            $this->ssl->setAcceptState();
        } else {
            $this->ssl->setConnectState();
        }
    }

    /**
     * Queues a single handshake step on the event loop.
     *
     * The step is never run inline: {@see advance()} sends through the transport, and with the test
     * and real transports emitting synchronously that would re-enter the peer's receive() — and back
     * into ours — mid-step, corrupting the engine's state. Deferring to a loop microtask lets the
     * current call stack unwind first, so each side advances on its own turn. The flag coalesces the
     * several datagrams of a flight into one step.
     */
    private function scheduleAdvance(): void
    {
        if ($this->advanceScheduled || $this->deferred->isComplete()) {
            return;
        }
        $this->advanceScheduled = true;
        EventLoop::queue(function (): void {
            $this->advanceScheduled = false;
            $this->advance();
        });
    }

    /**
     * Drives the handshake one step forward.
     *
     * Reached only through {@see scheduleAdvance()} — from the opening flight and from each arriving
     * datagram. A lost flight is recovered separately, by the retransmission timer re-sending it.
     * There is no polling: the only things that make progress are inbound data and an expired
     * deadline.
     */
    private function advance(): void
    {
        if ($this->deferred->isComplete()) {
            return;
        }
        try {
            if ($this->ssl->doHandshake()) {
                $this->cleanUp();
                $this->deferred->complete(true);
                return;
            }
            $this->sendBIOData();
        } catch (Throwable $e) {
            $this->teardown();
            $this->deferred->error(new HandshakeException("Handshake Failed", (int) $e->getCode(), $e));
            return;
        }
        // A deadline that has already elapsed is reported as 0.0, which a truthiness test
        // would discard and leave the flight unarmed.
        if ($this->timer === null && ($timeout = $this->ssl->dtlsV1GetTimeout()) !== null) {
            $this->handleDTLSTimeout($timeout);
        }
    }

    /**
     * Flushes every datagram the engine has queued out to the transport.
     *
     * A single flight is several datagrams, and the BIO hands them back one at a time, so this must
     * drain to empty: stopping after one would leave the rest of the flight sitting in the buffer,
     * and with nothing driving another send the peer would only ever see a partial flight until a
     * retransmission timer fired — turning every round trip into a one second stall.
     */
    private function sendBIOData(): void
    {
        while (($data = $this->bio->read()) !== null) {
            try {
                $this->transport->send($data);
            } catch (Exception) {
                // Silently handle transport send errors
            }
        }
    }

    /**
     * Handles DTLS timeout events.
     *
     * Sets up a timer to handle DTLS-specific timeout requirements. When the timer expires,
     * it processes the timeout and sends any pending BIO data.
     *
     * @param float $timeout The timeout duration in seconds
     */
    private function handleDTLSTimeout(float $timeout): void
    {
        $this->timer = EventLoop::delay($timeout, function () {
            $this->timer = null;
            $this->ssl->dtlsV1HandleTimeout();
            $this->sendBIOData();
            // With no poll to re-arm it, the timer has to schedule its own next backoff; otherwise
            // a second consecutive loss would never be retransmitted and the handshake would stall.
            if (($timeout = $this->ssl->dtlsV1GetTimeout()) !== null) {
                $this->handleDTLSTimeout($timeout);
            }
        });
    }

    /**
     * Cleans up resources after handshake completion.
     *
     * Removes event listeners, updates the TLS state, sends any remaining BIO data,
     * and cancels all active timers.
     */
    private function cleanUp(): void
    {
        $this->teardown();
        $this->tls->setState(TLSState::CONNECTED);
        $this->sendBIOData();
    }

    /**
     * Detaches from the transport and cancels the retransmission timer.
     *
     * Runs on both outcomes: after a successful handshake and, without the CONNECTED transition,
     * when one fails — so neither the data listener nor a pending timer is left dangling.
     */
    private function teardown(): void
    {
        $this->removeMessageListener();
        if ($this->timer !== null) {
            EventLoop::cancel($this->timer);
            $this->timer = null;
        }
    }

    /**
     * Removes the data event listener from the transport.
     */
    private function removeMessageListener(): void
    {
        $this->transport->removeListener('data', $this->listeners[0]);
    }
}