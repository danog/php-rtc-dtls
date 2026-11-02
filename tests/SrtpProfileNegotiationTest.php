<?php

namespace Tests\Webrtc\DTLS;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionProperty;
use Webrtc\DTLS\DTLS\Engine;
use Webrtc\DTLS\DTLS\RTCCertificate;
use Webrtc\DTLS\DTLS\Srtp;

/**
 * AES-256-GCM is preferred both ways: offered first as a client, chosen if offered as a server (whatever the
 * client's order), and AES-128-GCM otherwise (as with Telegram's SFU, which doesn't offer AES-256-GCM).
 */
#[CoversClass(Engine::class)]
#[CoversClass(Srtp::class)]
#[UsesClass(RTCCertificate::class)]
class SrtpProfileNegotiationTest extends TestCase
{
    private const AES_256_GCM = 0x0008;
    private const AES_128_GCM = 0x0007;
    private const AES128_CM_SHA1_80 = 0x0001;

    private static function engine(): Engine
    {
        // The profiles TLS offers: Srtp::getProfiles(), in their order.
        return new Engine(new RTCCertificate(), array_column(Srtp::getProfiles(), 'sslProfile'));
    }

    public function testTheClientOffersAes256GcmFirst(): void
    {
        $this->assertSame('SRTP_AEAD_AES_256_GCM', Srtp::getProfiles()[0]['sslProfile']);
        $extensions = (new ReflectionMethod(Engine::class, 'buildExtensions'))->invoke(self::engine(), true);
        // use_srtp (14): its profiles, then an empty MKI.
        $useSrtp = pack('nnn', 14, 9, 6).pack('nnn', self::AES_256_GCM, self::AES_128_GCM, self::AES128_CM_SHA1_80)."\0";
        $this->assertStringContainsString($useSrtp, $extensions);
    }

    public function testTheServerPicksAes256GcmIfOffered(): void
    {
        $this->assertSame('SRTP_AEAD_AES_256_GCM', self::negotiate([self::AES128_CM_SHA1_80, self::AES_128_GCM, self::AES_256_GCM]));
        $this->assertSame('SRTP_AEAD_AES_128_GCM', self::negotiate([self::AES128_CM_SHA1_80, self::AES_128_GCM]));
        $this->assertSame('SRTP_AES128_CM_SHA1_80', self::negotiate([self::AES128_CM_SHA1_80]));
        $this->assertSame('', self::negotiate([0x0002]));
    }

    /** @param list<int> $offered */
    private static function negotiate(array $offered): string
    {
        $engine = self::engine();
        $profiles = pack('n*', ...$offered);
        (new ReflectionMethod(Engine::class, 'negotiateSrtpProfile'))->invoke($engine, pack('n', \strlen($profiles)).$profiles."\0");
        return (new ReflectionProperty(Engine::class, 'selectedSrtpProfile'))->getValue($engine);
    }
}
