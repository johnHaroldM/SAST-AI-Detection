<?php

namespace App\Services\Scanner;

/**
 * A single rule hit at a point in a file.
 *
 * Deliberately does not carry the file path — the scanner owns that, so a
 * rule only has to reason about the node in front of it.
 */
final class RuleMatch
{
    public function __construct(
        public readonly int $line,
        public readonly ?string $message = null,
        public readonly ?string $snippet = null,
    ) {}
}
