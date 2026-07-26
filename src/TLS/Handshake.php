<?php

/**
 * This file is part of the PHP WebRTC package.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\DTLS\TLS;

use Exception;
use Amp\DeferredFuture;
use Revolt\EventLoop;
use Throwable;
use Webrtc\DTLS\Enum\SSLHandshakeState;
use Webrtc\DTLS\Exception\HandshakeException;
use Webrtc\ICE\RTCIceTransportInterface;
use Webrtc\Mixin\EventForwarder;
use Webrtc\SSL\Exception\OpenSSLException;
use Webrtc\SSL\Exception\WantReadException;
use Webrtc\SSL\Exception\WantWriteException;
use Webrtc\SSL\SSL\BIOInterface;
use Webrtc\SSL\SSL\SSLInterface;
use Webrtc\Stats\enum\TLSState;

/**
 * Class Handshake
 *
 * Manages the DTLS (Datagram Transport Layer Security) handshake process using an asynchronous event loop.
 * This class handles both client and server-side handshake operations, managing timeouts, BIO buffer operations,
 * and state transitions during the TLS handshake process.
 *
 * @package Webrtc\DTLS\TLS
 */
class Handshake
{
    use EventForwarder;

    /** @var DeferredFuture Settled when the handshake finishes or fails */
    private DeferredFuture $deferred;

    /** @var SSLInterface The SSL context for the handshake */
    private SSLInterface $ssl;

    /** @var RTCIceTransportInterface|null The transport layer for sending/receiving data */
    private ?RTCIceTransportInterface $transport;

    /** @var BIOInterface The BIO buffer for SSL operations */
    private BIOInterface $bio;

    /** @var string|null Handle of the periodic handshake status timer */
    private ?string $periodicCheck;

    /** @var string|null Handle of the retransmission timer */
    private ?string $timer = null;

    /** @var array Listeners for transport events */
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
        if ($this->timer) {
            EventLoop::cancel($this->timer);
            $this->timer = null;
        }

        $this->bio->write($bytes);
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
        $this->periodicCheckHandshakeStatus();
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
     * Periodically checks the handshake status.
     *
     * Sets up a periodic timer to check the handshake progress, sending/receiving data as necessary
     * and handling timeouts or errors that may occur during the process.
     */
    private function periodicCheckHandshakeStatus(): void
    {
        $this->periodicCheck = EventLoop::repeat(0.005, function (): void {
            try {
                $this->ssl->doHandshake();
                $this->cleanUp();
                $this->deferred->complete(true);
            } catch (WantReadException) {
                $this->sendBIOData();
            } catch (WantWriteException) {
                // Handshake needs more writing, handled by async loop
            } catch (Throwable $e) {
                $this->deferred->error(new HandshakeException("Handshake Failed", $e->getCode(), $e));
            }
            // A deadline that has already elapsed is reported as 0.0, which a truthiness test
            // would discard and leave the flight unarmed.
            if ($this->timer === null && ($timeout = $this->ssl->dtlsV1GetTimeout()) !== null) {
                $this->handleDTLSTimeout($timeout);
            }
        });
    }

    /**
     * Sends data from the BIO buffer to the transport.
     *
     * Reads any pending data from the BIO buffer and send it through the transport layer.
     * This is typically called when SSL indicates it has data ready to send.
     */
    private function sendBIOData(): void
    {
        if ($data = $this->bio->read()) {
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
            // A one-shot timer does not clear its own handle. Leaving it set made the guard in
            // periodicCheckHandshakeStatus() refuse to arm any further timer, so exactly one
            // flight was ever retransmitted and a second lost datagram stalled the handshake
            // for good.
            $this->timer = null;
            $this->ssl->dtlsV1HandleTimeout();
            $this->sendBIOData();
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
        $this->removeMessageListener();
        $this->tls->setState(TLSState::CONNECTED);
        $this->sendBIODataUntilEnd();

        EventLoop::cancel($this->periodicCheck);
        if ($this->timer) {
            EventLoop::cancel($this->timer);
        }
    }

    /**
     * Removes the data event listener from the transport.
     */
    private function removeMessageListener(): void
    {
        $this->transport->removeListener('data', $this->listeners[0]);
    }

    /**
     * Sends all remaining data from the BIO buffer.
     *
     * Continuously reads and sends any remaining data from the BIO buffer until it's empty.
     */
    private function sendBIODataUntilEnd(): void
    {
        while ($data = $this->bio->read()) {
            $this->transport->send($data);
        }
    }
}