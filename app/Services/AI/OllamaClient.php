<?php

namespace App\Services\AI;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use JsonException;
use RuntimeException;

/**
 * Thin wrapper around Ollama's local /api/chat endpoint. Forces
 * structured JSON output via the `format` schema param and temperature
 * 0 for repeatable classifications. Used by AtakeReviewer and
 * DepensaReviewer — never called directly from a controller.
 */
class OllamaClient
{
    /**
     * @param  array<int, array{role: string, content: string}>  $messages
     * @param  array<string, mixed>  $schema  JSON schema the model's reply must conform to.
     * @return array{content: array<string, mixed>, usage: array<string, mixed>, raw: array<string, mixed>}
     */
    public function chat(
        string $model,
        array $messages,
        array $schema,
        ?string $keepAlive = null,
        ?string $reviewer = null,
    ): array {
        if (! config('services.ollama.enabled')) {
            throw new RuntimeException('ANINO AI analysis is disabled.');
        }

        $url = rtrim(
            (string) config('services.ollama.url'),
            '/'
        );

        $reviewerName = in_array($reviewer, ['atake', 'depensa'], true)
            ? $reviewer
            : match ($model) {
                config('services.ollama.models.atake') => 'atake',
                config('services.ollama.models.depensa') => 'depensa',
                default => null,
            };

        $numGpu = $reviewerName !== null
            ? (int) config(
                "services.ollama.num_gpu.{$reviewerName}",
                20
            )
            : 20;

        try {
            $response = Http::acceptJson()
                ->asJson()
                ->timeout(
                    (int) config(
                        'services.ollama.timeout',
                        180
                    )
                )
                ->retry(
                    max(
                        1,
                        (int) config(
                            'services.ollama.retries',
                            1
                        )
                    ),
                    500,
                    throw: false
                )
                ->post($url.'/api/chat', [
                    'model' => $model,

                    'messages' => $messages,

                    'stream' => false,

                    'format' => $schema,

                    'keep_alive' => $keepAlive ?? (string) config(
                        'services.ollama.keep_alive',
                        '0'
                    ),

                    'options' => [
                        'temperature' => 0,

                        'num_ctx' => (int) config(
                            'services.ollama.num_ctx',
                            4096
                        ),

                        'num_predict' => (int) config(
                            'services.ollama.num_predict',
                            320
                        ),

                        'num_gpu' => $numGpu,
                    ],
                ]);
        } catch (ConnectionException $e) {
            throw new OllamaUnavailableException(
                'Unable to connect to Ollama.',
                previous: $e
            );
        }

        if (! $response->successful()) {
            if ($this->runtimeTerminated($response->body())) {
                throw new OllamaUnavailableException(
                    'Ollama model runtime terminated unexpectedly.'
                );
            }

            if (
                $response->status() === 404
                && str_contains(strtolower($response->body()), 'model')
                && str_contains(strtolower($response->body()), 'not found')
            ) {
                throw new OllamaUnavailableException(
                    'The configured Ollama model is not installed.'
                );
            }

            if (in_array($response->status(), [408, 429, 502, 503, 504], true)) {
                throw new OllamaUnavailableException(
                    'Ollama is temporarily unavailable (HTTP '.$response->status().').'
                );
            }

            throw new RuntimeException(
                sprintf(
                    'Ollama returned HTTP %d: %s',
                    $response->status(),
                    $response->body()
                )
            );
        }

        $content = $response->json('message.content');

        if (! is_string($content) || trim($content) === '') {
            throw new RuntimeException(
                'Ollama returned an empty message.'
            );
        }

        $decoded = $this->decodeStructuredContent(
            $content
        );

        return [
            'content' => $decoded,

            'usage' => [
                'prompt_eval_count' => $response->json(
                    'prompt_eval_count'
                ),

                'eval_count' => $response->json(
                    'eval_count'
                ),

                'total_duration' => $response->json(
                    'total_duration'
                ),

                'load_duration' => $response->json(
                    'load_duration'
                ),

                'prompt_eval_duration' => $response->json(
                    'prompt_eval_duration'
                ),

                'eval_duration' => $response->json(
                    'eval_duration'
                ),
            ],

            'raw' => $response->json(),
        ];
    }

    /**
     * Explicitly unload a model after its reviewer-major phase. This keeps the
     * two large local models from competing for the same constrained VRAM.
     */
    public function unload(string $model): void
    {
        if (! config('services.ollama.enabled')) {
            return;
        }

        $url = rtrim((string) config('services.ollama.url'), '/');

        try {
            $response = Http::acceptJson()
                ->asJson()
                ->timeout(30)
                ->post($url.'/api/generate', [
                    'model' => $model,
                    'keep_alive' => 0,
                ]);
        } catch (ConnectionException $e) {
            throw new OllamaUnavailableException(
                'Unable to connect to Ollama while unloading a model.',
                previous: $e,
            );
        }

        if (! $response->successful()) {
            throw new RuntimeException(sprintf(
                'Ollama returned HTTP %d while unloading model %s.',
                $response->status(),
                $model,
            ));
        }
    }

    private function runtimeTerminated(string $body): bool
    {
        $message = strtolower($body);

        return str_contains($message, 'llama-server process has terminated')
            || str_contains($message, 'cuda error: shared object initialization failed');
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeStructuredContent(
        string $content
    ): array {
        try {
            $decoded = json_decode(
                $content,
                true,
                flags: JSON_THROW_ON_ERROR
            );
        } catch (JsonException $error) {
            if (
                $error->getCode() !==
                JSON_ERROR_CTRL_CHAR
            ) {
                throw new RuntimeException(
                    'Ollama returned invalid structured JSON: '.
                    $error->getMessage(),
                    previous: $error
                );
            }

            try {
                $decoded = json_decode(
                    $this->escapeControlCharactersInStrings(
                        $content
                    ),
                    true,
                    flags: JSON_THROW_ON_ERROR
                );
            } catch (JsonException $retryError) {
                throw new RuntimeException(
                    'Ollama returned invalid structured JSON after control-character repair: '.
                    $retryError->getMessage(),
                    previous: $retryError
                );
            }
        }

        if (! is_array($decoded)) {
            throw new RuntimeException(
                'Ollama returned structured JSON with an invalid root value.'
            );
        }

        return $decoded;
    }

    private function escapeControlCharactersInStrings(
        string $json
    ): string {
        $result = '';
        $inString = false;
        $escaped = false;

        for (
            $index = 0,
            $length = strlen($json);
            $index < $length;
            $index++
        ) {
            $character = $json[$index];

            if (! $inString) {
                $result .= $character;

                if ($character === '"') {
                    $inString = true;
                }

                continue;
            }

            if ($escaped) {
                $result .= $character;
                $escaped = false;

                continue;
            }

            if ($character === '\\') {
                $result .= $character;
                $escaped = true;

                continue;
            }

            if ($character === '"') {
                $result .= $character;
                $inString = false;

                continue;
            }

            $codePoint = ord($character);

            $result .= $codePoint < 0x20
                ? sprintf(
                    '\\u%04X',
                    $codePoint
                )
                : $character;
        }

        return $result;
    }
}
