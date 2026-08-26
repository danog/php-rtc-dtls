<?php

/**
 * This file is part of the PHP WebRTC package, vendored and modified for MadelineProto.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\DTLS\SSL;

use Webrtc\DTLS\DTLS\RTCCertificate;
use Webrtc\DTLS\Enum\ContextMethod;
use Psr\Log\LoggerInterface;

/**
 * Configuration shared by every connection created from it.
 *
 * Upstream this wrapped an OpenSSL `SSL_CTX`. Since the DTLS engine is now written in PHP, it is
 * simply the place where the local certificate, the offered SRTP profiles and the logger live.
 */
class Context
{
    private ?RTCCertificate $certificate = null;

    private ?LoggerInterface $logger = null;

    /** SRTP protection profile names, in the colon separated form OpenSSL used. */
    private string $srtpProfiles = '';

    private string $cipherList = '';

    public function __construct(private readonly ContextMethod $method = ContextMethod::DTLS_METHOD)
    {
    }

    public function getMethod(): ContextMethod
    {
        return $this->method;
    }

    public function setCertificate(RTCCertificate $certificate): void
    {
        $this->certificate = $certificate;
    }

    public function getCertificate(): ?RTCCertificate
    {
        return $this->certificate;
    }

    public function setInfoCallBack(?LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function getLogger(): ?LoggerInterface
    {
        return $this->logger;
    }

    /**
     * Kept for interface compatibility: the peer certificate is pinned by fingerprint instead of
     * being validated against a chain, so there is no verification mode to configure.
     */
    public function setVerify(int $mode, callable $verify): void
    {
    }

    public function setCipherList(string $cipherList): void
    {
        $this->cipherList = $cipherList;
    }

    public function getCipherList(): string
    {
        return $this->cipherList;
    }

    public function setTlsextUseSrtp(string $profiles): void
    {
        $this->srtpProfiles = $profiles;
    }

    /**
     * @return list<string> The offered SRTP profile names.
     */
    public function getSrtpProfiles(): array
    {
        return $this->srtpProfiles === '' ? [] : explode(':', $this->srtpProfiles);
    }
}
