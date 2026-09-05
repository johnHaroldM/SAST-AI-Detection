<?php

namespace App\Services\Scanner\Rules;

use App\Services\Scanner\RuleMatch;
use PhpParser\Node;

/**
 * Dynamic value echoed without an escaping call in the expression.
 *
 * Only inspects the echoed expression itself, so `echo e($x)` and
 * `echo htmlspecialchars($x)` are clean while `echo $x` and
 * `echo "<b>{$x}</b>"` are flagged. Blade templates compile to PHP, but this
 * scanner reads .php sources directly, so `{!! !!}` is out of scope.
 */
class UnescapedOutputRule extends AbstractSecurityRule
{
    private const ESCAPERS = ['e', 'htmlspecialchars', 'htmlentities', 'strip_tags', 'json_encode', 'urlencode', 'rawurlencode'];

    public function id(): string
    {
        return 'php.laravel.security.xss-unescaped-output';
    }

    public function cweId(): int
    {
        return 79;
    }

    public function severity(): string
    {
        return 'MEDIUM';
    }

    public function description(): string
    {
        return 'Dynamic value rendered without HTML escaping';
    }

    public function inspect(Node $node): iterable
    {
        $expressions = match (true) {
            $node instanceof Node\Stmt\Echo_ => $node->exprs,
            $node instanceof Node\Expr\Print_ => [$node->expr],
            default => null,
        };

        if ($expressions === null) {
            return;
        }

        foreach ($expressions as $expression) {
            if (! $this->isDynamic($expression) || $this->containsEscaper($expression)) {
                continue;
            }

            yield new RuleMatch($node->getStartLine(), 'Unescaped dynamic value sent to output');

            return;
        }
    }

    private function containsEscaper(Node $expression): bool
    {
        if ($this->isFunctionNamed($expression, ...self::ESCAPERS)) {
            return true;
        }

        foreach ($expression->getSubNodeNames() as $name) {
            $child = $expression->{$name};

            foreach (is_array($child) ? $child : [$child] as $candidate) {
                if ($candidate instanceof Node && $this->containsEscaper($candidate)) {
                    return true;
                }
            }
        }

        return false;
    }
}
