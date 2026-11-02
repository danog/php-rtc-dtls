<?php

namespace Tests\Webrtc\DTLS;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Webrtc\DTLS\DTLS\Crypto;
use Webrtc\DTLS\DTLS\EcPrivateKey;

/**
 * The OpenSSL backend and the phpseclib fallback must agree: what one generates, signs or derives, the other
 * accepts. The handshake itself is checked against pion by {@see DtlsHandshakeTest}, with either backend
 * (PHP_RTC_CRYPTO_BACKEND=phpseclib).
 */
#[CoversClass(Crypto::class)]
#[CoversClass(EcPrivateKey::class)]
#[CoversClass(\Webrtc\DTLS\DTLS\Prf::class)]
#[\PHPUnit\Framework\Attributes\UsesClass(\Webrtc\DTLS\DTLS\RTCCertificate::class)]
#[\PHPUnit\Framework\Attributes\UsesClass(\Webrtc\Srtp\Aes::class)]
class CryptoTest extends TestCase
{
    private const DN = ['C' => 'US', 'ST' => 'Virginia', 'L' => 'Reston', 'O' => 'PHP WebRTC', 'CN' => 'webrtc.php'];

    private ?string $previousBackend = null;

    protected function setUp(): void
    {
        if (!\extension_loaded('openssl')) {
            $this->markTestSkipped('The openssl extension is required to compare the backends');
        }
        $this->previousBackend = Crypto::$backend;
    }

    protected function tearDown(): void
    {
        Crypto::$backend = $this->previousBackend;
    }

    /**
     * The backends: madeline_crypto's only if the extension is loaded.
     *
     * @return list<string>
     */
    private static function backends(): array
    {
        $backends = [Crypto::BACKEND_OPENSSL, Crypto::BACKEND_PHPSECLIB];
        if (\Webrtc\Srtp\Aes::nativeAvailable()) {
            $backends[] = Crypto::BACKEND_NATIVE;
        }
        return $backends;
    }

    /** @return iterable<string, array{string, string}> */
    public static function backendPairs(): iterable
    {
        foreach (self::backends() as $a) {
            foreach (self::backends() as $b) {
                yield "$a, then $b" => [$a, $b];
            }
        }
    }

    /**
     * @template T
     * @param callable(): T $operation
     * @return T
     */
    private static function with(string $backend, callable $operation): mixed
    {
        Crypto::$backend = $backend;
        return $operation();
    }

    #[DataProvider('backendPairs')]
    public function testAKeySerializedWithOneBackendUnserializesWithTheOther(string $a, string $b): void
    {
        $key = self::with($a, static fn () => EcPrivateKey::generateP256());
        $serialized = serialize($key);
        $unserialized = self::with($b, static fn () => unserialize($serialized));
        $this->assertInstanceOf(EcPrivateKey::class, $unserialized);
        $this->assertSame($key->getPoint(), $unserialized->getPoint());
        $this->assertSame($b === Crypto::BACKEND_OPENSSL, $unserialized->getOpenssl() !== null);
        $this->assertSame($b === Crypto::BACKEND_NATIVE, $unserialized->getNative() !== null);
    }

    #[DataProvider('backendPairs')]
    public function testTheBackendsAgreeOnEcdh(string $a, string $b): void
    {
        $ours = self::with($a, EcPrivateKey::generateP256(...));
        $theirs = self::with($b, EcPrivateKey::generateP256(...));
        $this->assertSame(65, \strlen($ours->getPoint()));
        $this->assertSame("\x04", $ours->getPoint()[0]);

        $secret = self::with($a, static fn () => $ours->computeSharedSecret($theirs->getPoint()));
        $this->assertSame(32, \strlen($secret));
        $this->assertSame($secret, self::with($b, static fn () => $theirs->computeSharedSecret($ours->getPoint())));
    }

    #[DataProvider('backendPairs')]
    public function testACertificateOfOneBackendVerifiesWithTheOther(string $a, string $b): void
    {
        $key = self::with($a, EcPrivateKey::generateP256(...));
        $pem = self::with($a, static fn () => Crypto::selfSign($key, self::DN, 30));
        $der = (string) base64_decode((string) preg_replace('#-----(BEGIN|END) CERTIFICATE-----|\s#', '', $pem), true);
        $signature = self::with($a, static fn () => $key->sign('signed data'));

        $expiry = self::with($b, static fn () => Crypto::getExpiry($pem));
        $this->assertGreaterThan(28, (new \DateTimeImmutable())->diff($expiry)->days);
        $this->assertTrue(self::with($b, static fn () => Crypto::verify($der, 'signed data', $signature, 'sha256')));
        $this->assertFalse(self::with($b, static fn () => Crypto::verify($der, 'other data', $signature, 'sha256')));

        // A key exported by one backend signs for the other.
        $reloaded = self::with($b, static fn () => EcPrivateKey::load($key->toPem()));
        $signature = self::with($b, static fn () => $reloaded->sign('signed data'));
        $this->assertTrue(self::with($a, static fn () => Crypto::verify($der, 'signed data', $signature, 'sha256')));
    }

    /** @return iterable<string, array{string, string}> */
    public static function backendsAndHashes(): iterable
    {
        foreach (self::backends() as $backend) {
            foreach (['sha1', 'sha256', 'sha384'] as $hash) {
                yield "$backend, $hash" => [$backend, $hash];
            }
        }
    }

    /**
     * Peers may use RSA certificates: their TLS 1.2 signatures are PKCS#1 v1.5.
     *
     * @param 'sha1'|'sha256'|'sha384' $hash
     */
    #[DataProvider('backendsAndHashes')]
    public function testRsaPkcs1SignaturesVerify(string $backend, string $hash): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $this->assertNotFalse($key);
        $csr = openssl_csr_new(['commonName' => 'peer'], $key, ['digest_alg' => 'sha256']);
        $this->assertNotFalse($csr);
        $this->assertNotTrue($csr);
        $certificate = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
        $this->assertNotFalse($certificate);
        $this->assertTrue(openssl_x509_export($certificate, $pem));
        $der = (string) base64_decode((string) preg_replace('#-----(BEGIN|END) CERTIFICATE-----|\s#', '', (string) $pem), true);
        $this->assertTrue(openssl_sign('signed data', $signature, $key, $hash));

        $this->assertTrue(self::with($backend, static fn () => Crypto::verify($der, 'signed data', (string) $signature, $hash)));
        $this->assertFalse(self::with($backend, static fn () => Crypto::verify($der, 'other data', (string) $signature, $hash)));
    }

    /** The fingerprint is the SHA-256 of the DER encoding, whatever the backend. */
    public function testTheFingerprintIsTheSha256OfTheDer(): void
    {
        $der = random_bytes(500);
        $this->assertSame(hash('sha256', $der, true), Crypto::sha256($der));
        $this->assertSame(
            strtoupper(implode(':', str_split(hash('sha256', $der), 2))),
            \Webrtc\DTLS\DTLS\RTCCertificate::fingerprint($der),
        );
    }

    /** RFC 5246's PRF (P_SHA256), natively or not, against a known vector. */
    public function testPrf(): void
    {
        // https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/
        $this->assertSame(
            'e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66',
            bin2hex(\Webrtc\DTLS\DTLS\Prf::prf(hex2bin('9bbe436ba940f017b17652849a71db35'), 'test label', hex2bin('a0ba9f936cda311827a6f796ffd5198c'), 100)),
        );
    }

    public function testAnInvalidEcdhPointIsRejected(): void
    {
        foreach (self::backends() as $backend) {
            $key = self::with($backend, EcPrivateKey::generateP256(...));
            $point = $key->getPoint();
            // Off the curve.
            $point[64] = \chr(\ord($point[64]) ^ 1);
            try {
                self::with($backend, static fn () => $key->computeSharedSecret($point));
                $this->fail("$backend accepted a point off the curve");
            } catch (\Throwable) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
