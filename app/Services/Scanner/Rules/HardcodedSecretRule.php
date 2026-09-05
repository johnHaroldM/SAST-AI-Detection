<?php

namespace App\Services\Scanner\Rules;

use App\Services\Scanner\RuleMatch;
use PhpParser\Node;

/**
 * Credential-looking name assigned a non-trivial string literal.
 *
 * Skips empty strings, obvious placeholders, and env()/config() reads, which
 * removes most of the noise this pattern would otherwise generate in config
 * files.
 */
class HardcodedSecretRule extends AbstractSecurityRule
{
    private const SECRET_HINTS = [
        'password', 'passwd', 'secret', 'token', 'apikey', 'api_key',
        'private_key', 'access_key', 'client_secret', 'auth',
    ];

    private const PLACEHOLDERS = [
        '', 'null', 'none', 'changeme', 'password', 'secret', 'your-key-here',
        'xxx', 'todo', 'example', 'test', 'placeholder',
    ];

    public function id(): string
    {
        return 'php.security.hardcoded-secret';
    }

    public function cweId(): int
    {
        return 798;
    }

    public function severity(): string
    {
        return 'HIGH';
    }

    public function description(): string
    {
        return 'Credential appears to be hardcoded in source';
    }

    public function inspect(Node $node): iterable
    {
        if (! $node instanceof Node\Expr\Assign && ! $node instanceof Node\Expr\ArrayItem) {
            return;
        }

        [$target, $value] = $node instanceof Node\Expr\Assign
            ? [$node->var, $node->expr]
            : [$node->key, $node->value];

        $name = $this->nameOf($target);

        if ($name === null || ! $this->looksSecret($name)) {
            return;
        }

        if (! $value instanceof Node\Scalar\String_) {
            return;
        }

        $literal = trim($value->value);

        if (strlen($literal) < 8 || in_array(strtolower($literal), self::PLACEHOLDERS, true)) {
            return;
        }

        // `'password' => 'required|min:6|confirmed'` and
        // `['current_password' => 'The current password is incorrect.']` both
        // match "credential-ish key, long string value" while containing no
        // credential at all. Without these two checks the rule is almost pure
        // noise in any Laravel codebase.
        if ($this->isValidationRuleset($literal) || $this->isSentence($literal)) {
            return;
        }

        yield new RuleMatch(
            line: $node->getStartLine(),
            message: "Hardcoded literal assigned to '{$name}'",
        );
    }

    private function nameOf(?Node $target): ?string
    {
        return match (true) {
            $target instanceof Node\Expr\Variable && is_string($target->name) => $target->name,
            $target instanceof Node\Expr\PropertyFetch && $target->name instanceof Node\Identifier => $target->name->toString(),
            $target instanceof Node\Scalar\String_ => $target->value,
            $target instanceof Node\Expr\ArrayDimFetch && $target->dim instanceof Node\Scalar\String_ => $target->dim->value,
            default => null,
        };
    }

    /**
     * A Laravel validation ruleset: pipe-delimited tokens drawn from the
     * validator vocabulary, e.g. "required|string|min:6|confirmed".
     */
    private function isValidationRuleset(string $literal): bool
    {
        if (! str_contains($literal, '|') && ! str_contains($literal, ':')) {
            return false;
        }

        $known = [
            'required', 'nullable', 'string', 'integer', 'numeric', 'boolean', 'array',
            'email', 'min', 'max', 'confirmed', 'unique', 'exists', 'same', 'size',
            'sometimes', 'date', 'image', 'file', 'mimes', 'mimetypes', 'regex', 'in',
            'digits', 'between', 'url', 'alpha', 'alpha_num', 'alpha_dash', 'present',
        ];

        foreach (explode('|', $literal) as $token) {
            $name = strtolower(trim(explode(':', $token, 2)[0]));

            if ($name !== '' && in_array($name, $known, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Prose rather than a credential — an error message or label. Real secrets
     * do not contain spaces followed by lowercase words and end in a period.
     */
    private function isSentence(string $literal): bool
    {
        return substr_count($literal, ' ') >= 2;
    }

    private function looksSecret(string $name): bool
    {
        $normalised = strtolower($name);

        foreach (self::SECRET_HINTS as $hint) {
            if (str_contains($normalised, $hint)) {
                return true;
            }
        }

        return false;
    }
}
