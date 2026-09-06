<?php

namespace App\Services\AI;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
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
        array $schema
    ): array {
        if (! config('services.ollama.enabled')) {
            throw new RuntimeException('ANINO AI analysis is disabled.');
        }

        $url = rtrim(
            (string) config('services.ollama.url'),
            '/'
        );

        try {
            $response = Http::acceptJson()
                ->asJson()
                ->timeout(
                    (int) config('services.ollama.timeout', 180)
                )
                ->retry(
                    (int) config('services.ollama.retries', 2),
                    500,
                    throw: false
                )
                ->post($url.'/api/chat', [
                    'model' => $model,

                    'messages' => $messages,

                    'stream' => false,

                    'format' => $schema,

                    'options' => [
                        'temperature' => 0,
                    ],
                ]);
        } catch (ConnectionException $e) {
            throw new RuntimeException(
                'Unable to connect to Ollama.',
                previous: $e
            );
        }

        if (! $response->successful()) {
            throw new RuntimeException(sprintf(
                'Ollama returned HTTP %d: %s',
                $response->status(),
                $response->body()
            ));
        }

        $content = $response->json('message.content');

        if (! is_string($content) || trim($content) === '') {
            throw new RuntimeException(
                'Ollama returned an empty message.'
            );
        }

        $decoded = json_decode(
            $content,
            true,
            flags: JSON_THROW_ON_ERROR
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
            ],

            'raw' => $response->json(),
        ];
    }
}
