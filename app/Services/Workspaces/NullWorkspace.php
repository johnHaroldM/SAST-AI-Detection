<?php

namespace App\Services\Workspaces;

/**
 * No source could be acquired for this scan.
 *
 * Ingestion still runs — findings are created and scored from scanner
 * metadata alone — but the AST and git-blame features fall back to neutral
 * defaults, which measurably weakens the feature vector. Kept as an explicit
 * type rather than a null return so the pipeline can record *why* a scan was
 * enriched poorly instead of silently producing weak vectors.
 */
final class NullWorkspace implements SourceWorkspace
{
    public function __construct(
        private string $expectedPath,
        private string $reason = 'no source available',
    ) {}

    public function path(): string
    {
        return $this->expectedPath;
    }

    public function isAvailable(): bool
    {
        return false;
    }

    public function driver(): string
    {
        return 'none';
    }

    public function reason(): string
    {
        return $this->reason;
    }

    public function release(): void
    {
        // Nothing acquired, nothing to clean up.
    }
}
