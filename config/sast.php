<?php

use App\Services\Scanner\Rules\CommandInjectionRule;
use App\Services\Scanner\Rules\HardcodedSecretRule;
use App\Services\Scanner\Rules\MassAssignmentRule;
use App\Services\Scanner\Rules\PathTraversalRule;
use App\Services\Scanner\Rules\SqlInjectionRule;
use App\Services\Scanner\Rules\UnescapedOutputRule;
use App\Services\Scanner\Rules\UnsafeDeserializationRule;
use App\Services\Scanner\Rules\WeakHashingRule;

return [

    /*
    |--------------------------------------------------------------------------
    | Model Training
    |--------------------------------------------------------------------------
    |
    | "min_training_samples" is the number of human-confirmed labels required
    | before a training run is allowed to proceed. Both classes must also be
    | represented — a single-class dataset produces a model that predicts one
    | label with total confidence, which is worse than no model at all.
    |
    | "retrain_batch_size" is how many new labels must accumulate before
    | TriageController auto-dispatches a retraining job.
    |
    */

    'training' => [
        'min_training_samples' => (int) env('SAST_MIN_TRAINING_SAMPLES', 50),
        'retrain_batch_size' => (int) env('SAST_RETRAIN_BATCH_SIZE', 100),
        'test_split_ratio' => 0.8,
        'model_path' => 'sast_triage_model.rbx',
    ],

    /*
    |--------------------------------------------------------------------------
    | Random Forest Hyperparameters
    |--------------------------------------------------------------------------
    */

    'forest' => [
        'max_tree_depth' => (int) env('SAST_FOREST_MAX_DEPTH', 10),
        'estimators' => (int) env('SAST_FOREST_ESTIMATORS', 100),
        'bagging_ratio' => (float) env('SAST_FOREST_BAGGING_RATIO', 0.5),

        // Real triage data is heavily skewed — most scanner hits are false
        // positives. Left unbalanced, each tree sees so few true positives
        // that the forest learns to answer "false positive" for everything
        // and still scores high accuracy. Balanced bootstrapping samples the
        // classes evenly per tree, trading raw accuracy for actually being
        // able to recognise the minority class.
        'balanced' => (bool) env('SAST_FOREST_BALANCED', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Rule Noise Thresholds
    |--------------------------------------------------------------------------
    |
    | Once a rule has been triaged at least "min_samples" times, its rolling
    | false-positive rate determines the recommended action surfaced on the
    | rule noise dashboard. Checked highest-first.
    |
    */

    'rules' => [
        'min_samples' => (int) env('SAST_RULE_MIN_SAMPLES', 20),
        'suppress_fp_rate' => (float) env('SAST_RULE_SUPPRESS_FP_RATE', 0.85),
        'review_fp_rate' => (float) env('SAST_RULE_REVIEW_FP_RATE', 0.70),
    ],

    /*
    |--------------------------------------------------------------------------
    | Automated PR Comments
    |--------------------------------------------------------------------------
    |
    | Findings must be predicted true positive at or above this confidence
    | before PostPrCommentsJob will comment on the commit. Everything below
    | stays in the in-app triage queue instead of adding noise to the PR.
    |
    */

    'pr_comments' => [
        'confidence_threshold' => (float) env('SAST_PR_CONFIDENCE_THRESHOLD', 0.80),
        'enabled' => (bool) env('SAST_PR_COMMENTS_ENABLED', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | CLI Upload Defaults
    |--------------------------------------------------------------------------
    |
    | Read by `sast:push` so a build agent can be configured through the
    | environment rather than by passing credentials as command arguments —
    | an argument ends up in shell history and CI logs, an env var does not.
    |
    */

    'cli' => [
        'endpoint' => env('SAST_ENDPOINT'),
        'ingest_token' => env('SAST_INGEST_TOKEN'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Ingest Credentials
    |--------------------------------------------------------------------------
    |
    | Upload tokens expire so that a credential pasted into a CI config years
    | ago stops working on its own. Revocation depends on somebody
    | remembering; expiry does not. Set to 0 for a non-expiring token.
    |
    */

    'ingest' => [
        'token_lifetime_days' => (int) env('SAST_INGEST_TOKEN_LIFETIME_DAYS', 90),
    ],

    /*
    |--------------------------------------------------------------------------
    | Built-in Scanner
    |--------------------------------------------------------------------------
    |
    | The bundled analyser walks a project's PHP source and applies the rules
    | below. Rules are intentionally syntactic and somewhat noisy — the ML
    | triage layer exists to learn which of their hits matter, so a
    | consistently noisy rule is more useful here than a clever quiet one.
    |
    */

    'scanner' => [
        'rules' => [
            SqlInjectionRule::class,
            CommandInjectionRule::class,
            UnsafeDeserializationRule::class,
            PathTraversalRule::class,
            UnescapedOutputRule::class,
            MassAssignmentRule::class,
            WeakHashingRule::class,
            HardcodedSecretRule::class,
        ],

        'exclude_directories' => [
            'vendor', 'node_modules', 'storage', 'bootstrap', 'public',
            '.git', '.github', 'dist', 'build', 'coverage', '_ide_helper',
            // Agent worktrees hold entire second copies of the project. Left
            // in, every finding is duplicated, and the near-identical rows
            // leak across the train/test split and inflate reported accuracy.
            '.claude', '.worktrees', '.idea', '.vscode',
        ],

        // Generated or minified PHP blows up parse time for no benefit.
        'max_file_bytes' => (int) env('SAST_SCANNER_MAX_FILE_BYTES', 1000000),

        // Ceiling on any single git blame/rev-list during enrichment, so one
        // pathological repository cannot stall an ingestion run.
        'git_timeout_seconds' => (int) env('SAST_SCANNER_GIT_TIMEOUT_SECONDS', 15),

        /*
        | Scanning a filesystem path chosen in the browser.
        |
        | Convenient on a developer machine, dangerous on a shared server:
        | it lets an authenticated user point the scanner at any directory
        | the PHP process can read and then view the contents in a report.
        | Leave enabled locally, disable in any hosted deployment, or pin
        | allowed_roots so paths outside them are rejected.
        */
        'local_scan' => [
            'enabled' => (bool) env('SAST_LOCAL_SCAN_ENABLED', true),

            // Empty means "anywhere the process can read". Set one or more
            // absolute prefixes to constrain it.
            'allowed_roots' => array_values(array_filter(
                explode(',', (string) env('SAST_LOCAL_SCAN_ROOTS', ''))
            )),

            // Scans run inline so the user gets results immediately; this is
            // the ceiling on that request.
            'timeout_seconds' => (int) env('SAST_LOCAL_SCAN_TIMEOUT', 300),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Source Workspaces
    |--------------------------------------------------------------------------
    |
    | The app is deployed away from the code it analyses, so source has to be
    | acquired per scan. "driver" selects how:
    |
    |   auto  - local checkout if one exists, otherwise git clone (default)
    |   local - only use an on-disk path; never reach the network
    |   git   - always clone, even if a local copy exists
    |   none  - never acquire source; AST/blame features stay at defaults
    |
    | For a hosted deployment no local path is ever set, so 'auto' resolves to
    | git on every scan. For local development, pointing a project at a
    | source_path avoids needing credentials at all.
    |
    */

    'workspace' => [
        'root' => env('SAST_WORKSPACE_ROOT', storage_path('app/workspaces')),
        'driver' => env('SAST_WORKSPACE_DRIVER', 'auto'),

        'git' => [
            // Off by default: cloning third-party code is opt-in.
            'enabled' => env('SAST_WORKSPACE_GIT_ENABLED', false),
            'binary' => env('SAST_GIT_BINARY', 'git'),

            // Remote URLs are built from this allowlist plus a validated
            // owner/repo slug — arbitrary URLs are never accepted, which
            // removes the SSRF surface rather than trying to filter it.
            'default_host' => env('SAST_GIT_DEFAULT_HOST', 'github.com'),
            'allowed_hosts' => array_filter(explode(',', (string) env(
                'SAST_GIT_ALLOWED_HOSTS',
                'github.com,gitlab.com,bitbucket.org'
            ))),

            'timeout_seconds' => (int) env('SAST_GIT_TIMEOUT_SECONDS', 300),
            'max_size_mb' => (int) env('SAST_GIT_MAX_SIZE_MB', 512),
        ],
    ],

    // Retained for backwards compatibility with anything still reading the
    // flat key; prefer sast.workspace.root.
    'workspace_root' => env('SAST_WORKSPACE_ROOT', storage_path('app/workspaces')),

];
