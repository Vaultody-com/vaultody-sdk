<?php

declare(strict_types=1);

/** A logger for the client's logger option that keeps every warning, so tests see them (and stderr stays quiet). */
final class RecordingLogger
{
    /** @var list<string> */
    public array $warnings = [];

    public function warning(string $message): void
    {
        $this->warnings[] = $message;
    }
}
