<?php

namespace Tests\Webrtc\DTLS;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\DTLS\DTLS\RTCCertificate;

#[CoversClass(RTCCertificate::class)]
class RTCCertificateTest extends TestCase
{
    public function testGenerate()
    {
        $certificate = new RTCCertificate();

        $expires = $certificate->expires();
        $this->assertInstanceOf(DateTimeImmutable::class, $expires);
        $now = new DateTimeImmutable();
        $diff = $now->diff($expires);
        $this->assertGreaterThan(28, $diff->days); // expires in a month

        $fingerprints = $certificate->getFingerprints();
        $this->assertCount(1, $fingerprints);
        $this->assertEquals('sha-256', $fingerprints[0]->algorithm);
        $this->assertEquals(95, strlen($fingerprints[0]->value));
    }

    public function testLoadCertificate()
    {
        $privateKey = __DIR__ . '/fixture/private_key.pem';
        $certificateFile = __DIR__ . '/fixture/certificate.pem';
        $certificate = new RTCCertificate($privateKey, $certificateFile);

        $expires = $certificate->expires();
        $this->assertInstanceOf(DateTimeImmutable::class, $expires);
        $this->assertEquals(
            new DateTimeImmutable('2046-07-21 13:03:38', new DateTimeZone('UTC')),
            $expires
        );

        $fingerprints = $certificate->getFingerprints();
        $this->assertCount(1, $fingerprints);
        $this->assertEquals('sha-256', $fingerprints[0]->algorithm);
        $this->assertEquals(
            '9E:B2:6E:15:58:C3:68:C6:A1:CE:FA:D1:BA:EC:C6:0C:EE:C6:19:EC:D2:EF:D7:03:11:A1:1F:B5:3D:9E:64:6B',
            $fingerprints[0]->value
        );
    }
}
