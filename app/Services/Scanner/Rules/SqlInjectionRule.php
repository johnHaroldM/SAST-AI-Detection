<?php

namespace App\Services\Scanner\Rules;

use App\Services\Scanner\RuleMatch;
use PhpParser\Node;

/**
 * Raw SQL built from something other than a fixed literal.
 *
 * Catches DB::raw/select/statement/unprepared and the query-builder escape
 * hatches (whereRaw, selectRaw, orderByRaw, havingRaw) when their first
 * argument is dynamic. Parameter-bound calls still match — deciding whether
 * bindings made a given call safe is exactly the judgement the triage model
 * is meant to learn.
 */
class SqlInjectionRule extends AbstractSecurityRule
{
    private const RAW_METHODS = [
        'raw', 'select', 'statement', 'unprepared', 'insert', 'update', 'delete',
    ];

    private const BUILDER_RAW_METHODS = [
        'whereraw', 'selectraw', 'orderbyraw', 'havingraw', 'groupbyraw', 'joinraw', 'fromraw',
    ];

    public function id(): string
    {
        return 'php.laravel.security.sql-injection';
    }

    public function cweId(): int
    {
        return 89;
    }

    public function severity(): string
    {
        return 'HIGH';
    }

    public function description(): string
    {
        return 'SQL statement assembled from dynamic input rather than bound parameters';
    }

    public function inspect(Node $node): iterable
    {
        $call = $this->asStaticCall($node, 'DB', ...self::RAW_METHODS)
            ?? $this->asMethodCall($node, ...self::BUILDER_RAW_METHODS)
            ?? $this->asMethodCall($node, 'raw')
            ?? $this->asFunctionCall($node, 'mysqli_query', 'pg_query');

        if ($call === null) {
            return;
        }

        // Procedural drivers put the query last (mysqli_query($link, $sql));
        // everything else puts it first.
        $argument = $call instanceof Node\Expr\FuncCall
            ? ($call->args[array_key_last($call->args)] ?? null)
            : ($call->args[0] ?? null);

        if ($argument === null || ! $this->isDynamic($argument)) {
            return;
        }

        yield new RuleMatch(
            line: $node->getStartLine(),
            message: $this->isBuiltString($argument)
                ? 'SQL string is concatenated or interpolated from variables'
                : 'Raw SQL receives a dynamic value',
        );
    }
}
