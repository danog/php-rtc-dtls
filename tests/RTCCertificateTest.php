<?php

namespace Tests\Webrtc\DTLS;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\DTLS\DTLS\Crypto;
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

    public function testSerialize()
    {
        // Calls are persisted along with the session, so their certificate must survive serialization.
        $certificate = new RTCCertificate();
        $unserialized = unserialize(serialize($certificate));

        $this->assertEquals($certificate->getFingerprints(), $unserialized->getFingerprints());
        $this->assertEquals($certificate->expires(), $unserialized->expires());
        $this->assertSame($certificate->getKey()->getPoint(), $unserialized->getKey()->getPoint());
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

    /**
     * A certificate serialized by 2.0.17/2.0.18 (with phpseclib, as OpenSSL keys couldn't be serialized), in the
     * session of MadelineProto 8.8.8: it loads, and its key works, with either backend.
     */
    public function testACertificateSerializedBefore2019Loads()
    {
        $certificate = unserialize((string) file_get_contents(__DIR__ . '/fixture/rtccertificate-2.0.18-phpseclib.ser'));
        $this->assertInstanceOf(RTCCertificate::class, $certificate);
        $this->assertEquals(
            'B9:B8:EF:88:2A:66:DE',
            substr($certificate->getFingerprints()[0]->value, 0, 20)
        );
        $signature = $certificate->getKey()->sign('signed data');
        $this->assertTrue(Crypto::verify($certificate->getDer(), 'signed data', $signature, 'sha256'));

        // And again in the current format.
        $certificate = unserialize(serialize($certificate));
        $this->assertTrue(Crypto::verify($certificate->getDer(), 'signed data', $certificate->getKey()->sign('signed data'), 'sha256'));
    }
}
