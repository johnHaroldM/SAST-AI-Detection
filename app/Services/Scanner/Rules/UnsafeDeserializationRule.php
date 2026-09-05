<?php

namespace App\Services\Scanner\Rules;

use App\Services\Scanner\RuleMatch;
use PhpParser\Node;

/**
 * unserialize() on anything that is not a fixed literal.
 *
 * Object injection is high impact and cheap to detect syntactically, which
 * makes this one of the rules where the scanner's precision is genuinely
 * good — useful contrast for the model against noisier rules.
 */
class UnsafeDeserializationRule extends AbstractSecurityRule
{
    public function id(): string
    {
        return 'php.security.unserialize-user-input';
    }

    public function cweId(): int
    {
        return 502;
    }

    public function severity(): string
    {
        return 'CRITICAL';
    }

    public function description(): string
    {
        return 'unserialize() applied to untrusted data allows object injection';
    }

    public function inspect(Node $node): iterable
    {
        $call = $this->asFunctionCall($node, 'unserialize');

        if ($call === null) {
            return;
        }

        $argument = $call->args[0] ?? null;

        if ($argument === null || ! $this->isDynamic($argument)) {
            return;
        }

        yield new RuleMatch(
            line: $node->getStartLine(),
            message: $this->readsRequestInput($argument)
                ? 'unserialize() called directly on request input'
                : 'unserialize() called on a dynamic value',
        );
    }
}
