<?php

namespace Tests\Webrtc\DTLS;

use PHPUnit\Framework\Assert;
use RuntimeException;

/**
 * Drives the pion-backed DTLS peer shipped in the reference/ directory.
 *
 * The DTLS stack here is hand-written on phpseclib rather than bound to OpenSSL, so the only
 * way to know its records are the ones a real peer expects is to hand them to one. This
 * wrapper starts that peer, waits for the events it reports, and tears it down again.
 */
final class DtlsPeer
{
    /** @var resource|null */
    private $process = null;

    /** @var array<int, resource> */
    private array $pipes = [];

    private function __construct(private readonly string $binary)
    {
    }

    /**
     * Locate the peer, or skip the calling test when it has not been built.
     */
    public static function locate(): self
    {
        $binary = getenv('PHP_RTC_REFERENCE_DTLS')
            ?: __DIR__ . '/../reference/bin/refpeer-dtls';

        if (!is_file($binary) || !is_executable($binary)) {
            Assert::markTestSkipped(
                'The DTLS reference peer is not built. Run: (cd reference && go build -o bin/refpeer-dtls ./cmd/refpeer-dtls)'
            );
        }

        return new self($binary);
    }

    /**
     * Start the peer in the given role.
     *
     * @param string $role "server" to have it listen, "client" to have it dial $address.
     * @param string|null $srtpProfiles Comma separated SRTP profiles to offer, if any.
     * @param string|null $address Where to dial, for the client role.
     * @return array{port: int, fingerprint: string} Its socket and certificate fingerprint.
     */
    public function start(string $role, ?string $srtpProfiles = null, ?string $address = null): array
    {
        $command = [$this->binary, '-role', $role];
        if ($srtpProfiles !== null) {
            $command[] = '-srtp';
            $command[] = $srtpProfiles;
        }
        if ($address !== null) {
            $command[] = '-addr';
            $command[] = $address;
        }

        $process = proc_open(
            $command,
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );

        if (!\is_resource($process)) {
            throw new RuntimeException("Could not start the DTLS reference peer at {$this->binary}");
        }

        stream_set_blocking($pipes[2], false);

        $this->process = $process;
        $this->pipes = $pipes;

        $listening = $this->await('listening');

        return ['port' => (int) $listening['port'], 'fingerprint' => $listening['fingerprint']];
    }

    /**
     * Block until the peer reports the named event.
     *
     * @return array<string, mixed> The event, so the caller can read what was negotiated.
     * @throws RuntimeException If the peer reports an error or exits first.
     */
    public function await(string $event, float $timeout = 20.0): array
    {
        $deadline = microtime(true) + $timeout;

        while (microtime(true) < $deadline) {
            $line = $this->readLine($deadline);
            if ($line === null) {
                continue;
            }

            $decoded = json_decode($line, true);
            if (!\is_array($decoded)) {
                continue;
            }

            if (($decoded['event'] ?? null) === 'error') {
                throw new RuntimeException("The DTLS reference peer failed: {$decoded['error']}");
            }
            if (($decoded['event'] ?? null) === $event) {
                return $decoded;
            }
        }

        throw new RuntimeException(
            "The DTLS reference peer never reported \"$event\": " . stream_get_contents($this->pipes[2])
        );
    }

    /**
     * Read one line without blocking past the deadline, so a peer that wedges fails the test
     * with a usable message instead of hanging the suite.
     */
    private function readLine(float $deadline): ?string
    {
        $read = [$this->pipes[1]];
        $write = $except = [];
        $remaining = max(0.0, $deadline - microtime(true));

        if (stream_select($read, $write, $except, (int) $remaining, (int) (fmod($remaining, 1) * 1e6)) < 1) {
            return null;
        }

        $line = fgets($this->pipes[1]);

        return $line === false ? null : trim($line);
    }

    public function stop(): void
    {
        if ($this->process === null) {
            return;
        }

        foreach ($this->pipes as $pipe) {
            if (\is_resource($pipe)) {
                fclose($pipe);
            }
        }
        proc_terminate($this->process);
        proc_close($this->process);

        $this->process = null;
        $this->pipes = [];
    }

    public function __destruct()
    {
        $this->stop();
    }
}
