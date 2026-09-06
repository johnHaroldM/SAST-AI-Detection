<?php

namespace App\Services\AI;

/**
 * Redacts obvious secrets from source text before it's persisted to
 * finding_ai_contexts or sent to Ollama. Even though Ollama runs
 * locally, the raw prompt and response still land in our own database
 * and logs — this is about not writing live credentials there, not
 * about the AI model's trustworthiness.
 *
 * Deliberately pattern-based and conservative: it's meant to catch the
 * obvious cases (keys, tokens, private key blocks) without trying to be
 * a full secret-scanning engine. False positives (over-redacting) are
 * an acceptable trade-off here; false negatives on real credentials are
 * not.
 */
class SecretRedactor
{
    /**
     * @var array<string, string> Pattern => label used in the replacement text.
     */
    private const PATTERNS = [
        // Private key blocks (RSA, EC, OpenSSH, generic PEM).
        '/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/' => 'PRIVATE_KEY',

        // JSON Web Tokens.
        '/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/' => 'JWT',

        // AWS access key IDs and secret-looking assignments.
        '/AKIA[0-9A-Z]{16}/' => 'AWS_ACCESS_KEY_ID',
        '/(?i)aws_secret_access_key\s*[:=]\s*[\'"]?[A-Za-z0-9\/+=]{30,}[\'"]?/' => 'AWS_SECRET_ACCESS_KEY',

        // GitHub / GitLab tokens.
        '/gh[pousr]_[A-Za-z0-9]{36,}/' => 'GITHUB_TOKEN',
        '/glpat-[A-Za-z0-9_-]{20,}/' => 'GITLAB_TOKEN',

        // Slack tokens.
        '/xox[baprs]-[A-Za-z0-9-]{10,}/' => 'SLACK_TOKEN',

        // Stripe live keys.
        '/sk_live_[A-Za-z0-9]{20,}/' => 'STRIPE_SECRET_KEY',

        // Google API keys.
        '/AIza[0-9A-Za-z_-]{35}/' => 'GOOGLE_API_KEY',

        // Generic api_key / secret / token assignments (var = "value").
        '/(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[\'"][A-Za-z0-9_\-\/+=]{12,}[\'"]/' => 'API_KEY_OR_TOKEN',

        // Password literals.
        '/(?i)password\s*[:=]\s*[\'"][^\'"]{3,}[\'"]/' => 'PASSWORD',

        // Authorization headers.
        '/(?i)authorization\s*:\s*(Bearer|Basic)\s+\S+/' => 'AUTHORIZATION_HEADER',

        // Database / service connection URLs with embedded credentials.
        '/(?i)\b(mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s\'"]*:[^\s\'"]*@[^\s\'"]+/' => 'CONNECTION_STRING',
    ];

    public function redact(string $text): string
    {
        foreach (self::PATTERNS as $pattern => $label) {
            $text = preg_replace(
                $pattern,
                "[REDACTED:{$label}]",
                $text
            ) ?? $text;
        }

        return $text;
    }
}
