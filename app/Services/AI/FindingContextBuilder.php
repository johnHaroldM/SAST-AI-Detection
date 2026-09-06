<?php

namespace App\Services\AI;

use App\Models\Finding;
use Illuminate\Support\Str;

/**
 * Builds the compact evidence package ATAKE/DEPENSA reason over — never
 * the full repository. Source text is redacted (see SecretRedactor)
 * before it's assembled, since this payload gets persisted to
 * finding_ai_contexts as well as sent to Ollama.
 *
 * The ±50-line window here is the documented first pass; see project
 * notes for the planned AST-based upgrade (containing function/class,
 * source/sink expressions, sanitizer calls, route/middleware context).
 */
class FindingContextBuilder
{
    public function __construct(
        private readonly SecretRedactor $redactor = new SecretRedactor(),
    ) {}

    /**
     * @return array{context: string, metadata: array<string, mixed>, hash: string}
     */
    public function build(
        Finding $finding,
        ?string $workspacePath
    ): array {
        $maxChars = (int) config(
            'services.ollama.max_context_chars',
            24000
        );

        $sourceContext = $this->extractSourceContext(
            $finding,
            $workspacePath
        );

        $payload = [
            'finding' => [
                'id' => $finding->id,
                'rule_id' => $finding->rule_id,
                'cwe_id' => $finding->cwe_id,
                'severity' => $finding->severity,
                'file_path' => $finding->file_path,
                'line_number' => $finding->line_number,
                'message' => $this->redactor->redact(
                    (string) $finding->message
                ),
                'raw_snippet' => $this->redactor->redact(
                    (string) $finding->raw_snippet
                ),
            ],

            'static_analysis' => [
                'feature_vector' => $finding->feature_vector,

                'rubix_tp_probability' =>
                    $finding->tp_probability,

                'rubix_predicted_label' =>
                    $finding->predicted_label,
            ],

            'source_context' => $sourceContext,
        ];

        $context = json_encode(
            $payload,
            JSON_PRETTY_PRINT
            | JSON_UNESCAPED_SLASHES
            | JSON_THROW_ON_ERROR
        );

        // Prevent giant prompts.
        $context = Str::limit(
            $context,
            $maxChars,
            "\n...[context truncated]..."
        );

        return [
            'context' => $context,

            'metadata' => [
                'finding_id' => $finding->id,
                'file_path' => $finding->file_path,
                'line_number' => $finding->line_number,
            ],

            'hash' => hash('sha256', $context),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function extractSourceContext(
        Finding $finding,
        ?string $workspacePath
    ): array {
        if (
            ! $workspacePath
            || ! is_dir($workspacePath)
            || ! $finding->file_path
        ) {
            return [
                'available' => false,
                'reason' => 'source workspace unavailable',
            ];
        }

        $relative = ltrim(
            str_replace('\\', '/', $finding->file_path),
            '/'
        );

        $file = rtrim($workspacePath, DIRECTORY_SEPARATOR)
            .DIRECTORY_SEPARATOR
            .$relative;

        if (! is_file($file)) {
            return [
                'available' => false,
                'reason' => 'finding source file not found',
            ];
        }

        $lines = @file($file);

        if (! is_array($lines)) {
            return [
                'available' => false,
                'reason' => 'unable to read source file',
            ];
        }

        $line = max(1, (int) $finding->line_number);

        // Start with ±50 lines. Improve later using AST
        // function boundaries.
        $start = max(1, $line - 50);
        $end = min(count($lines), $line + 50);

        $snippet = [];

        for ($i = $start; $i <= $end; $i++) {
            $snippet[] = sprintf(
                '%6d | %s',
                $i,
                rtrim($lines[$i - 1])
            );
        }

        return [
            'available' => true,
            'start_line' => $start,
            'end_line' => $end,
            'code' => $this->redactor->redact(
                implode("\n", $snippet)
            ),
        ];
    }
}
