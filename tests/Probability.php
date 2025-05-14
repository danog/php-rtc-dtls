<?php

namespace Tests\Webrtc\DTLS;

class Probability {
    private array $queue = [];
    private int $index = 0;
    private int $percentage;
    private int $batchSize = 1;

    public function __construct(int $percentage) {
        $this->percentage = $percentage;
        $this->generateQueue();
    }

    private function generateQueue(): void {
        $happenCount = round($this->batchSize * ($this->percentage / 100));
        $this->queue = array_merge(array_fill(0, $happenCount, true), array_fill(0, $this->batchSize - $happenCount, false));
        shuffle($this->queue);
        $this->index = 0;
    }

    public function probabilityHappen(): bool {
        if ($this->index >= count($this->queue)) {
            $this->batchSize *= 2;
            $this->generateQueue();
        }

        return $this->queue[$this->index++];
    }

    public function setBatchSize(int $batchSize): void
    {
        $this->batchSize = $batchSize;
    }
}
