<?php

namespace App\Services\Scanner\Rules;

use App\Services\Scanner\RuleMatch;
use PhpParser\Node;

/**
 * Shell execution with a dynamically built command.
 *
 * Also flags backticks (`Node\Expr\ShellExec`), which are easy to miss in
 * review and always execute a shell.
 */
class CommandInjectionRule extends AbstractSecurityRule
{
    private const SHELL_FUNCTIONS = [
        'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec',
    ];

    public function id(): string
    {
        return 'php.security.command-injection';
    }

    public function cweId(): int
    {
        return 78;
    }

    public function severity(): string
    {
        return 'CRITICAL';
    }

    public function description(): string
    {
        return 'Shell command built from dynamic input';
    }

    public function inspect(Node $node): iterable
    {
        if ($node instanceof Node\Expr\ShellExec) {
            yield new RuleMatch($node->getStartLine(), 'Backtick shell execution');

            return;
        }

        $call = $this->asFunctionCall($node, ...self::SHELL_FUNCTIONS);

        if ($call === null) {
            return;
        }

        $argument = $call->args[0] ?? null;

        if ($argument === null || ! $this->isDynamic($argument)) {
            return;
        }

        yield new RuleMatch($node->getStartLine(), 'Shell command receives a dynamic value');
    }
}
