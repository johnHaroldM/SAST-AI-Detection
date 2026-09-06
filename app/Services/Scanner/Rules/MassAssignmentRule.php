<?php

namespace App\Services\Scanner\Rules;

use App\Services\Scanner\RuleMatch;
use PhpParser\Node;

/**
 * Model hydrated straight from request input.
 *
 * Deliberately noisy: a model with a well-chosen $fillable makes this
 * perfectly safe, and most Laravel codebases do exactly that. It is included
 * *because* it produces a high false-positive rate — the rule-noise feedback
 * loop needs rules like this to have something to learn from.
 */
class MassAssignmentRule extends AbstractSecurityRule
{
    private const ASSIGNING_METHODS = ['create', 'fill', 'update', 'forcecreate', 'firstorcreate', 'updateorcreate'];

    public function id(): string
    {
        return 'php.laravel.security.mass-assignment';
    }

    public function cweId(): int
    {
        return 915;
    }

    public function severity(): string
    {
        return 'MEDIUM';
    }

    public function description(): string
    {
        return 'Model populated directly from request input without an explicit field list';
    }

    public function inspect(Node $node): iterable
    {
        $call = $this->asStaticCall($node, null, ...self::ASSIGNING_METHODS)
            ?? $this->asMethodCall($node, ...self::ASSIGNING_METHODS);

        if ($call === null) {
            return;
        }

        foreach ($call->args as $argument) {
            if ($this->readsRequestInput($argument)) {
                yield new RuleMatch(
                    line: $node->getStartLine(),
                    message: 'Request input passed wholesale into a model write',
                );

                return;
            }
        }
    }
}
