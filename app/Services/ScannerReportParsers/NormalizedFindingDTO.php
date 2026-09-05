<?php

namespace App\Services\ScannerReportParsers;

/**
 * Scanner-agnostic representation of a single finding, produced by every
 * ScannerReportParser implementation regardless of source format.
 */
final class NormalizedFindingDTO
{
    public function __construct(
        public readonly string $ruleId,
        public readonly ?int $cweId,
        public readonly string $filePath,
        public readonly int $lineNumber,
        public readonly string $severity,   // normalized to LOW|MEDIUM|HIGH|CRITICAL
        public readonly string $message,
        public readonly ?string $snippet,
    ) {}
}
