# Project Scope and Change Log

This folder contains definitive scope and change documentation for the SAST AI Detection app.
It is the primary reference for future sessions and should be used before making assumptions about feature scope or implementation details.

## Purpose

- Define the current system scope.
- List the main features already implemented or intended.
- Capture what was added or changed in the current branch.
- Prevent AI hallucination by providing a single source of truth.

## Current System Scope

### Core features

- Static Application Security Testing (SAST) triage engine built in Laravel.
- `Rubix ML` model for predicting true positive vs false positive findings.
- AST-based feature extraction via `nikic/php-parser` and related services.
- Scan ingestion pipeline that normalizes SARIF, Semgrep, SonarQube, Bandit, and PHPCS.
- Background job-based processing and model training.
- Inertia + React frontend for authenticated dashboard and scan upload pages.
- Feature vector builder and model trainer services in PHP.
- Authenticated web routes for scan dashboard and upload.
- Existing GitHub Actions workflow at `.github/workflows/tests.yml` for CI checks.

### Important implementation details

- The model pipeline uses Rubix ML (`Pipeline`: OneHotEncoder → ZScaleStandardizer → RandomForest) wrapped in a `PersistentModel`, saved to `storage/app/sast_triage_model.rbx`.
- Tunables live in `config/sast.php` (training minimums, forest hyperparameters, rule noise thresholds, PR-comment threshold, workspace root). Nothing ML-related is hardcoded any more.
- Rubix's probability method is `proba()`, not `predictProbabilities()`. `Pipeline` transforms its `Dataset` **in place**, so `predict()` and `proba()` must never be called on the same `Dataset` instance — `RubixTriageService::probabilitiesFor()` makes a single `proba()` pass and takes the argmax.
- `findings.rule_id` stores the scanner's **native rule string**, not a numeric FK. `Finding::rule()` and `Rule::findings()` join on `rules.external_id`.
- Cold start is a supported state: before the first training run, scans still ingest and vectorize, and findings stay unscored (`predicted_label = null`) in the triage queue.
- `routes/api.php` is loaded under the **`web`** middleware group with an `/api` prefix (see the `then` closure in `bootstrap/app.php`), so those endpoints use session auth and stay CSRF-protected. There is no Sanctum in this project.
- The scan upload route is `GET /scans/upload`, rendered by `App\Http\Controllers\Web\ScanDashboardController::create()`.
- The upload form posts to the Inertia route `POST /scans` (`scans.store`), **not** to `/api/scans` — Inertia requires a redirect response and the API returns 202 JSON. Both paths share `StoreScanRequest` and `ScanIngestionService`.
- `resources/js/app.jsx` is the Inertia entry point, globbing `./pages/**` (lowercase — the directory is `resources/js/pages`).
- The frontend uses `@inertiajs/react` v2 and does not support `setLayoutProps` or `useHttp` exports.

### Training the model

1. `php artisan db:seed --class=SastDemoSeeder` — seeds 160 labeled findings if you need a dataset to start from.
2. Triage findings in the UI (`/scans/{id}`) or via `POST /api/findings/{id}/triage`.
3. Train from `/model` in the UI, or `php artisan sast:train --sync` (add nothing for the queued variant on `ml-training`).
4. Training requires ≥ `sast.training.min_training_samples` labels **and** both classes present; otherwise it raises `InsufficientTrainingDataException` and reports the shortfall.
5. Retraining auto-dispatches once `sast.training.retrain_batch_size` new labels accumulate *since the last `ModelState`*.

## Current branch additions and changes

### CI/CD documentation

- Added `docs/ci.md` with explicit local commands and pipeline notes.
- Updated `README.md` with a CI/CD section and testing guidance.

### Tests

- `tests/Feature/ModelTrainingTest.php` — readiness accounting, cold start, training guards, a real Rubix fit asserting F1 > 0.7 on separable data, and the training endpoints.
- `tests/Feature/ScanIngestionPipelineTest.php` — upload validation, SARIF parsing, feature-vector construction, rule registration, and the `Finding`↔`Rule` join.
- `tests/Feature/TriageFeedbackLoopTest.php` — triage decisions becoming training labels, rule FP-rate recalculation, threshold ordering, and auto-retrain gating.
- `tests/Feature/ScanUploadTest.php` — authenticated access to `/scans/upload` and guest redirect.
- Factories exist for `Scan`, `Finding` (`vectorized()`, `labeled()`, `scored()` states), `Rule`, `ModelState`, and `Project`.

### Triage queue (added 2026-08-02)

The labelling workflow that feeds the model.

- `Web\TriageQueueController` → `GET /triage`, renders `Triage/Queue`. Spans every scan, grouped by rule, focusing the highest-volume rule by default. Filters by rule, project and severity; ordered by file/line/id so paging never reshuffles mid-review.
- `App\Services\Triage\TriageGuidance` — per-CWE criteria for what makes a finding a true or false positive. Keyed on CWE rather than rule id so it also covers findings ingested from external scanners.
- `TriageController::destroy` → `DELETE /api/findings/{finding}/triage`. Retracts a label, deletes the feedback row, and recomputes the rule's FP rate. A wrong label is worse than no label, so retraction must leave no residue.
- `ConfidenceSignal` renders an explicit `n/a` state when `tp_probability` is null. Showing `0%` would read as "the model is confident this is a false positive" — a much stronger claim than "nothing has scored this yet" — and would anchor the reviewer's judgement.

Keyboard: `J`/`K` navigate, `T`/`F` label, `U` undo. Decisions are optimistic with rollback on failure.

### Built-in scanner (added 2026-08-01)

The app now produces findings itself instead of only ingesting external reports.

- `App\Services\Scanner\SecurityRule` — interface: `id()`, `cweId()`, `severity()`, `description()`, `inspect(Node)`.
- `AbstractSecurityRule` — shared shape matching. The `as*` helpers (`asFunctionCall`, `asStaticCall`, `asMethodCall`) return a narrowed node rather than a bool, so callers keep the type when reaching `->args`.
- Eight rules under `App\Services\Scanner\Rules`, covering CWE-89, 78, 502, 22, 79, 915, 327, 798.
- `ProjectScanner` — one parse and one traversal per file, offering every node to every rule. Tracks `filesScanned()` and `skippedFiles()` so coverage claims are honest.
- `SarifReportWriter` — emits SARIF 2.1.0. The scanner deliberately writes a report rather than inserting findings directly, so there is exactly one ingestion path in the system.
- `sast:scan` command — `{project?} --path= --branch= --sync --dry-run`.
- Rules are registered in `config/sast.php` under `scanner.rules` and constructed in `AppServiceProvider`.

Rules are **syntactic, not taint analysis**, and this is intentional: the ML triage layer exists to learn which shapes matter in a given codebase. `mass-assignment` and `weak-hashing` are included precisely because they are noisy — the rule-noise feedback loop needs rules with a real false-positive rate to have anything to learn.

One fidelity note: SARIF's `level` vocabulary has no CRITICAL, so `SarifReportWriter` carries the original severity and CWE in result `properties`, and `SarifReportParser` prefers those when present. Without this every CRITICAL finding silently downgrades to HIGH on ingest.

### Source workspaces (added 2026-08-01)

The app acquires source per scan instead of assuming it is present, so it works the same on a laptop and on a hosted server where the code lives in someone else's repository.

- `App\Services\Workspaces\SourceWorkspace` — interface: `path()`, `isAvailable()`, `driver()`, `release()`.
- `LocalPathWorkspace` — `projects.source_path`, or a cached checkout under the workspace root. Never deletes anything.
- `GitCloneWorkspace` — shallow fetch of the exact `commit_sha`, falling back to the branch when a server rejects fetch-by-SHA. Always deletes its checkout.
- `NullWorkspace` — explicit "no source", carrying the reason, so weak vectors are explainable rather than silent.
- `SourceWorkspaceFactory` — resolution order under the `auto` driver: project `source_path` → cached checkout → git clone → null.
- `ProcessScanJob::handle()` now takes a fourth argument (`SourceWorkspaceFactory`) and releases the workspace in a `finally`.
- Config lives at `sast.workspace.*`; `sast.workspace_root` is kept as a compatibility alias.
- Migration `2026_08_01_141714_add_source_columns_to_projects_table` adds `projects.vcs_host` and `projects.source_path`.

Security invariants, all covered by tests in `tests/Feature/SourceWorkspaceTest.php`:
- Remote URLs are built from an allowlisted host plus a validated `owner/repo` slug — arbitrary URLs are never accepted.
- Access tokens travel in `GIT_CONFIG_*` env vars, never argv, and are redacted from logs.
- `timeout_seconds` bounds the entire acquisition, not each git call.
- `release()` refuses to delete anything whose basename is not a `scan-*` scratch directory.
- Deletion materialises the file list before unlinking; iterating and deleting at once made the iterator skip entries and leak disk.

### Known gaps

- **No multi-tenancy.** `Project` has no owner/team/org, so every authenticated user can see every project. This is the main blocker before hosting it for more than one user, along with per-tenant quotas on clone size and frequency.
- No archive-upload workspace provider, so repositories the app cannot reach over the network cannot be scanned.
- `package.json` has no `lint:check` / `format:check` / `types:check` scripts, so `composer ci:check` fails on its npm steps even though Pint, PHPStan, and the test suite all pass.

## How to use this document

1. Read this file before making changes or answering questions.
2. If a requested feature is not listed here, do not assume it exists.
3. Refer to actual files in the codebase for implementation details.
4. When updating the project, add a clear `docs/scope/CHANGELOG.md` entry if behavior or scope changes.
