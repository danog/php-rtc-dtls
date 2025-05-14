<?php

namespace Tests\Webrtc\DTLS;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Webrtc\DTLS\RTCCertificate;

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
            DateTimeImmutable::createFromFormat('Y-m-d H:i:s.u', '2026-03-14 00:31:17.000000'),
            $expires
        );

        $fingerprints = $certificate->getFingerprints();
        $this->assertCount(1, $fingerprints);
        $this->assertEquals('sha-256', $fingerprints[0]->algorithm);
        $this->assertEquals(
            '80:D6:8B:31:64:AA:3C:A8:39:17:C0:DC:B2:D9:2D:31:32:10:24:F5:E1:8E:DF:39:20:F8:9D:75:D1:57:C1:9E',
            $fingerprints[0]->value
        );
    }
}
