<?php

namespace App\Services\Scanner;

use PhpParser\Node;

/**
 * One security pattern the built-in scanner looks for.
 *
 * Rules are intentionally *syntactic*, not a taint analysis: they flag shapes
 * that are frequently vulnerable, accepting that many hits will be false
 * positives. That is the entire premise of this application — the ML triage
 * layer exists to learn which of these shapes matter in a given codebase, so
 * a noisy-but-consistent rule is more useful here than a clever one.
 *
 * Each rule sees every node of every parsed file exactly once.
 */
interface SecurityRule
{
    /**
     * Stable scanner-native identifier, e.g. "php.laravel.security.sql-injection".
     * This becomes findings.rule_id and is matched to rules.external_id.
     */
    public function id(): string;

    public function cweId(): ?int;

    /**
     * LOW | MEDIUM | HIGH | CRITICAL
     */
    public function severity(): string;

    public function description(): string;

    /**
     * @return iterable<RuleMatch>
     */
    public function inspect(Node $node): iterable;
}
