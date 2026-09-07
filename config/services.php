<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Resend, Postmark, AWS, and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'key' => env('POSTMARK_API_KEY'),
    ],

    'resend' => [
        'key' => env('RESEND_API_KEY'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

    'ollama' => [
        'enabled' => (bool) env(
            'ANINO_AI_ENABLED',
            false
        ),

        'url' => env(
            'OLLAMA_URL',
            'http://127.0.0.1:11434'
        ),

        'timeout' => (int) env(
            'ANINO_AI_TIMEOUT',
            env('OLLAMA_TIMEOUT', 180)
        ),

        'retries' => (int) env(
            'ANINO_AI_RETRIES',
            env('OLLAMA_RETRIES', 1)
        ),

        'queue' => env(
            'ANINO_AI_QUEUE',
            'ai-analysis'
        ),

        'max_context_chars' => (int) env(
            'ANINO_AI_MAX_CONTEXT_CHARS',
            4500
        ),

        'context_lines' => (int) env(
            'ANINO_AI_CONTEXT_LINES',
            20
        ),

        'max_findings_per_run' => (int) env(
            'ANINO_AI_MAX_FINDINGS_PER_RUN',
            10
        ),

        'num_ctx' => (int) env(
            'ANINO_AI_NUM_CTX',
            4096
        ),

        'num_predict' => (int) env(
            'ANINO_AI_NUM_PREDICT',
            320
        ),

        'keep_alive' => env(
            'ANINO_AI_KEEP_ALIVE',
            '0'
        ),

        // Keep one reviewer resident only while its model-major phase runs.
        'phase_keep_alive' => env(
            'ANINO_AI_PHASE_KEEP_ALIVE',
            '5m'
        ),

        // One shared local runtime prevents separate scans from competing for
        // constrained VRAM. Give each Ollama host its own key when scaling out.
        'runtime_lock' => env(
            'ANINO_AI_RUNTIME_LOCK',
            'anino-ollama-runtime'
        ),

        'job_timeout' => (int) env(
            'ANINO_AI_JOB_TIMEOUT',
            420
        ),

        'stale_after' => (int) env(
            'ANINO_AI_STALE_AFTER',
            480
        ),

        'models' => [
            'atake' => env(
                'ANINO_ATAKE_MODEL',
                env(
                    'OLLAMA_ATAKE_MODEL',
                    'llama3.1:8b'
                )
            ),

            'depensa' => env(
                'ANINO_DEPENSA_MODEL',
                env(
                    'OLLAMA_DEPENSA_MODEL',
                    'llama3.1:8b'
                )
            ),
        ],

        'num_gpu' => [
            'atake' => (int) env(
                'ANINO_ATAKE_NUM_GPU',
                20
            ),

            'depensa' => (int) env(
                'ANINO_DEPENSA_NUM_GPU',
                20
            ),
        ],
    ],

];
