<?php

/**
 * This file is part of the PHP WebRTC package.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\DTLS\SSL;

use Webrtc\DTLS\Exception\ZeroReturnException;

interface SSLInterface
{
    public function setAcceptState(): void;

    public function setConnectState(): void;

    /**
     * Advance the handshake by one step.
     *
     * @return bool True once the handshake is complete, false if it still needs another datagram
     *              from the peer.
     */
    public function doHandshake(): bool;

    public function getPeerCertificateDigest(): ?string;

    public function getSelectedSrtpProfile(): string;

    public function exportKeyingMaterial(string $label, int $keyLength, ?string $context = null): string;

    public function shutdown(): bool ;

    public function dtlsV1GetTimeout(): ?float ;

    public function dtlsV1HandleTimeout(): bool ;

    /**
     * Return any decrypted application data buffered so far.
     *
     * The incoming datagram must already have been written to the BIO. The engine coalesces
     * application data into a single stream, so there is at most one chunk to hand back per call.
     *
     * @return string|null The decrypted application data, or null if none has arrived.
     * @throws ZeroReturnException If the peer has closed the connection.
     */
    public function readApplicationData(): ?string;

    public function write(string $buf, int $flags = 0): void;
}