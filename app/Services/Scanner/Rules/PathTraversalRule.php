<?php

namespace App\Services\Scanner\Rules;

use App\Services\Scanner\RuleMatch;
use PhpParser\Node;

/**
 * Filesystem or include target built from a dynamic value.
 *
 * include/require with a dynamic path is treated as CRITICAL because it is
 * remote code execution rather than mere file disclosure.
 */
class PathTraversalRule extends AbstractSecurityRule
{
    private const FILE_FUNCTIONS = [
        'file_get_contents', 'file_put_contents', 'fopen', 'unlink', 'readfile',
        'file', 'copy', 'rename', 'rmdir', 'mkdir', 'scandir', 'opendir',
    ];

    public function id(): string
    {
        return 'php.security.path-traversal';
    }

    public function cweId(): int
    {
        return 22;
    }

    public function severity(): string
    {
        return 'HIGH';
    }

    public function description(): string
    {
        return 'Filesystem path or include target derived from dynamic input';
    }

    public function inspect(Node $node): iterable
    {
        if ($node instanceof Node\Expr\Include_) {
            if ($this->isDynamic($node->expr)) {
                yield new RuleMatch($node->getStartLine(), 'Dynamic include/require can execute arbitrary files');
            }

            return;
        }

        $call = $this->asFunctionCall($node, ...self::FILE_FUNCTIONS);

        if ($call === null) {
            return;
        }

        $argument = $call->args[0] ?? null;

        if ($argument === null || ! $this->isDynamic($argument)) {
            return;
        }

        // A bare variable is weaker evidence than a path visibly stitched
        // together, so the message distinguishes them for the reviewer.
        yield new RuleMatch(
            line: $node->getStartLine(),
            message: $this->isBuiltString($argument)
                ? 'File path is concatenated from dynamic parts'
                : 'File operation receives a dynamic path',
        );
    }
}
