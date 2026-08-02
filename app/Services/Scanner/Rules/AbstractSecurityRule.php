<?php

namespace App\Services\Scanner\Rules;

use App\Services\Scanner\SecurityRule;
use PhpParser\Node;

/**
 * Shared shape-matching helpers.
 *
 * The recurring question across every rule is "is this expression a fixed
 * literal, or could it carry attacker-controlled data?". A literal string is
 * safe by construction; anything built from variables, concatenation, or
 * interpolation is worth flagging. This is a heuristic, not proof — see the
 * note on SecurityRule about why that is the intended design here.
 */
abstract class AbstractSecurityRule implements SecurityRule
{
    public function cweId(): ?int
    {
        return null;
    }

    public function severity(): string
    {
        return 'MEDIUM';
    }

    /**
     * True when the expression is anything other than a fixed literal —
     * a variable, a concatenation, an interpolated string, a method call.
     */
    protected function isDynamic(?Node $expr): bool
    {
        if ($expr === null) {
            return false;
        }

        // `strlen(...)` first-class callable syntax — no argument was passed
        // at all, so there is nothing dynamic to flag.
        if ($expr instanceof Node\VariadicPlaceholder) {
            return false;
        }

        if ($expr instanceof Node\Arg) {
            $expr = $expr->value;
        }

        return ! $expr instanceof Node\Scalar\String_
            && ! $expr instanceof Node\Scalar\Int_
            && ! $expr instanceof Node\Scalar\Float_
            && ! $expr instanceof Node\Expr\ConstFetch
            && ! $expr instanceof Node\Expr\ClassConstFetch;
    }

    /**
     * String built by concatenation or "{$interpolation}" — the classic
     * injection shape, and a stronger signal than a bare variable.
     */
    protected function isBuiltString(?Node $expr): bool
    {
        if ($expr instanceof Node\Arg) {
            $expr = $expr->value;
        }

        return $expr instanceof Node\Expr\BinaryOp\Concat
            || $expr instanceof Node\Scalar\InterpolatedString
            || $expr instanceof Node\Expr\AssignOp\Concat;
    }

    /**
     * The as* helpers return the narrowed node instead of a bool so callers
     * can reach ->args and ->name without the type being lost.
     */
    protected function asFunctionCall(Node $node, string ...$names): ?Node\Expr\FuncCall
    {
        if (! $node instanceof Node\Expr\FuncCall || ! $node->name instanceof Node\Name) {
            return null;
        }

        return $this->matchesName($node->name->toString(), $names) ? $node : null;
    }

    /**
     * Static call such as DB::raw(...) or Model::create(...).
     */
    protected function asStaticCall(Node $node, ?string $class, string ...$methods): ?Node\Expr\StaticCall
    {
        if (! $node instanceof Node\Expr\StaticCall || ! $node->name instanceof Node\Identifier) {
            return null;
        }

        if ($class !== null) {
            $called = $node->class instanceof Node\Name ? $node->class->getLast() : null;

            if (strcasecmp((string) $called, $class) !== 0) {
                return null;
            }
        }

        return $this->matchesName($node->name->toString(), $methods) ? $node : null;
    }

    protected function asMethodCall(Node $node, string ...$methods): ?Node\Expr\MethodCall
    {
        if (! $node instanceof Node\Expr\MethodCall || ! $node->name instanceof Node\Identifier) {
            return null;
        }

        return $this->matchesName($node->name->toString(), $methods) ? $node : null;
    }

    protected function isFunctionNamed(Node $node, string ...$names): bool
    {
        return $this->asFunctionCall($node, ...$names) !== null;
    }

    protected function isMethodNamed(Node $node, string ...$methods): bool
    {
        return $this->asMethodCall($node, ...$methods) !== null;
    }

    /**
     * Variadics can carry string keys when spread with named arguments, so
     * array-key is the accurate shape here rather than a list.
     *
     * @param  array<array-key, string>  $candidates
     */
    private function matchesName(string $name, array $candidates): bool
    {
        return in_array(strtolower($name), array_map('strtolower', $candidates), true);
    }

    /**
     * Recognises request input: $request->all(), request()->input(), $_GET,
     * $_POST, $_REQUEST — the sources most worth caring about in Laravel.
     */
    protected function readsRequestInput(?Node $expr): bool
    {
        if ($expr instanceof Node\VariadicPlaceholder) {
            return false;
        }

        if ($expr instanceof Node\Arg) {
            $expr = $expr->value;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return in_array($expr->name, ['_GET', '_POST', '_REQUEST', '_COOKIE'], true);
        }

        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            return $this->readsRequestInput($expr->var);
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->isMethodNamed($expr, 'all', 'input', 'get', 'query', 'post', 'json');
        }

        return false;
    }
}
