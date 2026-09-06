<?php

namespace App\Services\Scanner\Rules;

use App\Services\Scanner\RuleMatch;
use PhpParser\Node;

/**
 * Broken hash primitives.
 *
 * md5/sha1 are frequently legitimate — cache keys, ETags, checksums — so this
 * rule only escalates to HIGH when the surrounding expression mentions a
 * credential. Another deliberately noisy rule for the model to calibrate.
 */
class WeakHashingRule extends AbstractSecurityRule
{
    private const WEAK = ['md5', 'sha1', 'crc32'];

    private const CREDENTIAL_HINTS = ['password', 'passwd', 'secret', 'token', 'credential', 'apikey', 'api_key'];

    public function id(): string
    {
        return 'php.security.weak-hashing';
    }

    public function cweId(): int
    {
        return 327;
    }

    public function severity(): string
    {
        return 'LOW';
    }

    public function description(): string
    {
        return 'Cryptographically broken hash function';
    }

    public function inspect(Node $node): iterable
    {
        $call = $this->asFunctionCall($node, ...self::WEAK);

        if ($call === null) {
            return;
        }

        $name = $call->name instanceof Node\Name ? $call->name->toString() : 'hash';

        yield new RuleMatch(
            line: $call->getStartLine(),
            message: $this->looksCredentialRelated($call)
                ? "{$name}() appears to hash a credential"
                : "{$name}() is cryptographically broken",
        );
    }

    private function looksCredentialRelated(Node\Expr\FuncCall $node): bool
    {
        foreach ($node->args as $argument) {
            if (! $argument instanceof Node\Arg) {
                continue;
            }

            $value = $argument->value;

            $candidate = match (true) {
                $value instanceof Node\Expr\Variable && is_string($value->name) => $value->name,
                $value instanceof Node\Expr\PropertyFetch && $value->name instanceof Node\Identifier => $value->name->toString(),
                $value instanceof Node\Expr\ArrayDimFetch && $value->dim instanceof Node\Scalar\String_ => $value->dim->value,
                default => null,
            };

            if ($candidate === null) {
                continue;
            }

            foreach (self::CREDENTIAL_HINTS as $hint) {
                if (str_contains(strtolower($candidate), $hint)) {
                    return true;
                }
            }
        }

        return false;
    }
}
