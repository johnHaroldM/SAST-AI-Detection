# SAST Triage Engine — Core Implementation

This implements the controller logic and core algorithms from the architecture plan.

## File Map

| File | Purpose | Roadmap Phase |
|---|---|---|
| `app/Services/ScannerReportParsers/*` | Normalizes SARIF/Semgrep/SonarQube/Bandit/PHPCS into a common DTO | Phase 1 |
| `app/Services/AstFeatureExtractor.php` | AST walker (nikic/php-parser): cyclomatic complexity, sanitizer detection, scope depth | Phase 1 |
| `app/Services/GitBlameAuthorResolver.php` | `git blame` based author-experience feature | Phase 1 |
| `app/Services/FeatureVectorBuilder.php` | Assembles the full 9-field feature vector per finding | Phase 2 |
| `app/Console/Commands/BuildDatasetCommand.php` | `php artisan sast:build-dataset` | Phase 2 |
| `app/Services/RubixTriageService.php` | **Core ML engine**: vectorize → RandomForest candidate → project-group validation → quality-gated deployment | Phase 2 & 3 |
| `app/Console/Commands/TrainSastModelCommand.php` | `php artisan sast:train` | Phase 2 |
| `app/Services/RubixTrainingDatasetExporter.php` | Reproducible trusted train/validation export, quarantine, and review-acquisition queue | Phase 2 & 3 |
| `app/Console/Commands/ExportRubixTrainingDatasetCommand.php` | `php artisan sast:export-rubix-dataset` | Phase 2 & 3 |
| `app/Jobs/ProcessScanJob.php` | Full async ingestion pipeline (parse → AST enrich → vectorize → predict) | Phase 1–3 |
| `app/Jobs/TrainSastModelJob.php` | Background retraining, auto-triggered every 100 new labels | Phase 3 |
| `app/Http/Controllers/ScanController.php` | Upload endpoint + polling + filtered findings list | Phase 1 |
| `app/Http/Controllers/TriageController.php` | **Human-in-the-loop feedback loop** — single & bulk override endpoints that write `TriageFeedback` and trigger retraining | Phase 3 |
| `app/Http/Controllers/RuleController.php` | Rule noise ranking (`GET /api/rules/noisy`) | Phase 4 |
| `app/Jobs/PostPrCommentsJob.php` | GitHub commit-comment posting, gated at >80% TP confidence | Phase 4 |
| `app/Models/*` | `Scan`, `Finding`, `Rule` (with `recalculateFpRate()`), `TriageFeedback`, `ModelState` | All phases |
| `routes/api.php` | Wires all controllers | — |

## Key algorithmic decisions worth flagging to your ML engineer

1. **Cyclomatic complexity** is computed via AST node counting (`if`/`for`/`foreach`/`while`/`case`/`catch`/`&&`/`||`/ternary), not a regex heuristic — see `AstFeatureExtractor::cyclomaticComplexity()`.
2. **Sanitizer detection** is a fixed allowlist of function/method names (`AstFeatureExtractor::SANITIZER_FUNCTIONS`). This is intentionally naive (no taint tracking) — it's a *feature* for the classifier, not a ground-truth sanitization proof. Worth expanding per-CWE.
3. **Rule noise feedback loop**: every triage decision calls `Rule::recalculateFpRate()`, which both feeds `historical_fp_rate_rule` back into future feature vectors *and* flags rules for `suppress`/`review_config` once ≥20 samples and >70%/85% FP rates are reached (config-driven thresholds).
4. **Retraining is never synchronous** — `TriageController` only ever dispatches `TrainSastModelJob`, gated by a cache lock (`sast:retrain-lock`) so concurrent triage submissions don't queue duplicate training runs.
5. **PR comments are decoupled from scoring** — `PostPrCommentsJob` is a separate queue (`vcs-integrations`) so a GitHub API outage can't fail the ML pipeline, and it has its own retry/backoff policy.

## Not yet implemented (flagged, not hidden)
- `Project` model / VCS credential storage (referenced by `PostPrCommentsJob`, assumed to exist from your auth/orgs setup).
- SonarQube/Bandit/PHPCS parsers are functional but less battle-tested than the SARIF reference parser — worth a closer review pass before Phase 1 sign-off.
- Migrations aren't included here — the schema is implied by the `$fillable` arrays in each model; happy to generate them next if useful.

---

## Frontend — React + Inertia.js

| File | Purpose |
|---|---|
| `resources/js/app.jsx` | Inertia entry point, mounts pages from `resources/js/Pages` |
| `resources/js/Layouts/AppLayout.jsx` | Sidebar shell every page renders inside |
| `resources/js/Components/ConfidenceSignal.jsx` | Signature gauge rendering `tp_probability` as a scan-line reading, with a tick at the 80% auto-PR-comment threshold from `PostPrCommentsJob` |
| `resources/js/Components/SeverityBadge.jsx` | LOW/MEDIUM/HIGH/CRITICAL badge |
| `resources/js/Pages/Scans/Index.jsx` | Scan list with triage-progress counts |
| `resources/js/Pages/Scans/Show.jsx` | **Core triage screen**: filterable/expandable findings table, single and bulk approve/reject, optimistic UI |
| `resources/js/Pages/Rules/Noisy.jsx` | Rule noise ranking view, mirrors `RuleController::noisy()` |
| `app/Http/Controllers/Web/ScanDashboardController.php` | Renders `Scans/Index` and `Scans/Show` with Inertia — reuses the same Eloquent queries as the JSON API controllers |
| `app/Http/Controllers/Web/RuleDashboardController.php` | Renders `Rules/Noisy` |
| `routes/web.php` | Page routes (session-authenticated) |
| `tailwind.config.js`, `resources/css/app.css` | Design tokens |

### Design notes
Built for a security engineer working a review queue, not a marketing surface — dense, fast, low-chrome. Palette is ink/panel dark with semantic accents (amber = pending, red = confirmed true positive, green = confirmed false positive); type pairs Space Grotesk (headers) with Inter (UI) and IBM Plex Mono (file paths, rule IDs, CWE codes, confidence %). The **Confidence Signal** bar is the one deliberately custom element — a scan-line gauge instead of a generic progress bar, with a threshold tick showing exactly where a finding crosses into "auto-posted to the PR" territory.

Triage actions in `Scans/Show.jsx` POST directly to the existing `TriageController` JSON endpoints (`/api/findings/{id}/triage`, `/api/findings/bulk-triage`) with optimistic local state, rather than full Inertia page reloads — keeps a long review session fast.

### Setup
```bash
composer require inertiajs/inertia-laravel
npm install
npm run dev   # or `npm run build` for production
```
Add the `HandleInertiaRequests` middleware and `@routes`/`@inertiaHead`/`@inertia` Blade directives per the [Inertia Laravel adapter docs](https://inertiajs.com/server-side-setup) if not already present in your app.

### CI / Pipeline
The repo already includes a GitHub Actions workflow at `.github/workflows/tests.yml` that runs on push to `main` and on pull requests.

The pipeline performs:
- PHP and Composer setup on `php:8.5`
- Node setup on `node:22`
- `composer setup` to install dependencies, set up `.env`, migrate the database, and build frontend assets
- `composer ci:check` to run linting, static analysis, and automated tests

Use these commands locally to mirror CI:
```bash
composer setup
composer ci:check
composer test
php artisan test --filter=ScanUploadTest --compact
npm run build
```

The scan upload page is covered by `tests/Feature/ScanUploadTest.php`, which validates authenticated access to `/scans/upload` and guest redirect behavior.

---

## Training the model

The classifier starts untrained. Scans still ingest and vectorize during that cold-start phase — findings just queue up unscored until there are enough human labels to fit a model.

```bash
# 1. Optional UI/demo data only; these unattributed labels cannot certify a model
php artisan db:seed --class=SastDemoSeeder

# 2. Label real findings, check readiness, then train
php artisan sast:train --sync     # runs in-process, prints the metrics table
php artisan sast:train            # queues onto `ml-training` instead
```

Or use the **Model** screen at `/model`, which separates the active certified model from the latest attempt and shows validation support, precision/recall/F1, the confusion matrix, rejection reasons, and candidate history.

Training refuses to run unless there are at least `sast.training.min_training_samples` labeled findings **and** both classes are represented — a single-class fit produces a model that answers the same label at full confidence for everything. Both cases raise `InsufficientTrainingDataException`, which the job treats as a skip rather than a failure.

Training is candidate-based. Exact repeated scanner findings are deduplicated, a complete project+commit group is assigned to either training or validation (never both), and evaluation uses the same probability decision used by production. A candidate is deployed only when its TP flags clear both `SAST_MIN_DEPLOY_PRECISION` (80% by default) and `SAST_MIN_DEPLOY_FLAGS` (5 by default) at `SAST_TP_FLAG_THRESHOLD` (80% by default), with true-positive validation support from at least two independent project groups. A failed candidate is recorded as `rejected` and cannot replace the active model. Legacy model files remain score-only: their numbers are advisory and their automatic label is left blank for human review.

Labels come from triage: every human decision in the UI (or `POST /api/findings/{id}/triage`) upserts one canonical `TriageFeedback` row, sets `final_label`, and recomputes that rule's rolling false-positive rate, which feeds `historical_fp_rate_rule` back into future feature vectors. Certification data must have matching `human`, `benchmark`, or `import` provenance; direct/demo labels without that evidence are excluded. Retraining auto-dispatches once `sast.training.retrain_batch_size` new labels accumulate since the last recorded `ModelState`. AI-promoted weak labels carry `source=ai_pseudo`; they may augment only the capped training side and never count as independent validation evidence.

### Exporting a Rubix training dataset

Create a private, reproducible dataset package from the same deduplication and project+commit split used by Rubix:

```bash
php artisan sast:export-rubix-dataset
php artisan sast:export-rubix-dataset --output=rubix-training/review-v1 --validation-percent=20 --review-limit=0
```

The command writes `train.jsonl`, `validation.jsonl`, `review_queue.jsonl`, a human-friendly `review_queue.csv`, `quarantine.jsonl`, and `manifest.json` beneath `storage/app/private`. Only matching human/benchmark/import labels enter the machine-training partitions. AI pseudo-labels, unknown provenance, and inconsistent labels are quarantined; unlabeled findings have blank labels and advisory scores only. Exact repeated findings are collapsed, secrets in review excerpts are redacted, CSV formula cells are neutralized, and the manifest records feature order, class/group support, ambiguity warnings, and SHA-256 hashes for every data file.

This export is read-only. Completing `human_label` in the CSV does not update the database automatically; review through the triage UI (or a separately validated import workflow) before retraining.

### Configuration

Everything tunable lives in [config/sast.php](config/sast.php): training minimums, stable validation percentage, deployment precision/support gates, RandomForest hyperparameters, rule noise thresholds, the PR-comment confidence gate (off by default), and the source workspace root.

## ATAKE / DEPENSA AI review

ATAKE and DEPENSA are advisory Ollama reviewers that run after scan ingestion saves the compact AI context for each finding. ATAKE checks exploitability from an offensive perspective; DEPENSA checks for false-positive evidence from a defensive perspective; the adjudicator combines their outputs.

```bash
ollama pull chrisdiochavez/ANINOGPT-PILIPINAS-ATAKE:latestv3
ollama pull chrisdiochavez/ANINOGPT-PILIPINAS-DEPENSA:latestv5-lightweight
```

Set these values in `.env`, then restart Laravel and the queue worker:

```bash
ANINO_AI_ENABLED=true
OLLAMA_URL=http://127.0.0.1:11434
ANINO_AI_TIMEOUT=600
ANINO_AI_MAX_CONTEXT_CHARS=4500
ANINO_AI_CONTEXT_LINES=20
ANINO_AI_MAX_FINDINGS_PER_RUN=10
ANINO_AI_NUM_CTX=4096
ANINO_AI_NUM_PREDICT=320
ANINO_AI_KEEP_ALIVE=0
ANINO_AI_PHASE_KEEP_ALIVE=5m
ANINO_AI_RUNTIME_LOCK=anino-ollama-runtime
ANINO_AI_JOB_TIMEOUT=900
ANINO_AI_STALE_AFTER=960
ANINO_AI_RETRIES=1
ANINO_ATAKE_MODEL=chrisdiochavez/ANINOGPT-PILIPINAS-ATAKE:latestv3
ANINO_DEPENSA_MODEL=chrisdiochavez/ANINOGPT-PILIPINAS-DEPENSA:latestv5-lightweight
ANINO_ATAKE_NUM_GPU=20
ANINO_DEPENSA_NUM_GPU=20
DB_QUEUE_RETRY_AFTER=1920
SAST_AI_TRAINING_CONFIDENCE_THRESHOLD=0.85
```

`ANINO_*_NUM_GPU=20` matches the current 4 GB development GPU; tune it for the Ollama host instead of copying it blindly. Queue reservation time must remain greater than the longest worker timeout.

`composer dev` starts separate workers for normal jobs, AI review, and model training. To run them manually, use separate terminals:

```bash
php artisan queue:work --queue=default,vcs-integrations --tries=1 --timeout=600
php artisan queue:work --queue=ai-analysis --tries=3 --timeout=900
php artisan queue:work --queue=ml-training --tries=1 --timeout=1800
```

New scans queue ATAKE/DEPENSA automatically when `ANINO_AI_ENABLED=true`. For an existing completed scan, open `/scans/{scan}` and use **Run AI review**. Each run reviews the highest-risk unreviewed slice first, capped by `ANINO_AI_MAX_FINDINGS_PER_RUN`. The persisted cursor runs all ATAKE steps first and then all DEPENSA steps, one inference per job. Completed results with the same model, prompt, and context fingerprint are reused after an interruption. A shared runtime lock prevents different scans from competing for the same Ollama GPU. Expand a finding to see the ATAKE, DEPENSA, and adjudicator cards once the queue finishes.

The supplied ATAKE and lightweight DEPENSA models are both roughly 8B Q4 models. CPU-only inference can still take one or two minutes per reviewer. During a reviewer phase the active model stays warm for five minutes; at the model boundary it is explicitly unloaded before the other model starts. This avoids keeping both models in constrained VRAM. Lower `ANINO_AI_NUM_PREDICT` or `ANINO_AI_CONTEXT_LINES` carefully if more speed is needed.

Use **Teach Rubix** on the scan page to record high-confidence adjudicator TP/FP results as provenance-marked `ai_pseudo` weak labels and queue a candidate evaluation. `needs_validation`, low-confidence rows, already triaged findings, and findings without feature vectors are ignored. Weak labels never count as independent validation evidence, so they cannot certify their own model.

### Flagging ATAKE and DEPENSA for training

Each ATAKE and DEPENSA card has feedback controls for **Accurate**, **Correct answer TP**, **Correct answer FP**, **Missing context**, and retraction. Feedback is attached to the exact assessment and does not overwrite `findings.final_label`. The dashboard reports Rubix-vs-AI agreement separately from human-verified outcomes; `ai_pseudo` labels never count as human verification.

Export reviewed examples as deterministic, redacted JSONL files:

```bash
php artisan sast:export-ai-feedback --reviewer=all
php artisan sast:export-ai-feedback --reviewer=atake --output=anino-training/atake-v1 --validation-percent=20
```

The exporter writes one file per reviewer plus `manifest.json` under the local storage disk. It includes only completed assessments with explicit human feedback or trusted human/imported triage labels, keeps each project+commit in one train/validation split, removes known secrets, excludes raw Ollama responses, stale context fingerprints, and AI-promoted pseudo-labels, and deduplicates the latest reviewer+context pair.

This command prepares supervised data; it does not mutate an Ollama model. Fine-tune ATAKE and DEPENSA separately with their matching JSONL file, evaluate the held-out split, publish immutable model tags, then update `ANINO_ATAKE_MODEL` and `ANINO_DEPENSA_MODEL` only after the new versions pass evaluation.

### Notes for whoever picks this up next

- Rubix's probability method is `proba()`, not `predictProbabilities()`.
- `Pipeline` transforms its `Dataset` **in place** — calling `predict()` and then `proba()` on the same `Dataset` double-transforms the samples and fails on a dimensionality mismatch. `RubixTriageService::probabilitiesFor()` makes one `proba()` pass and takes the argmax.
- `findings.rule_id` holds the scanner's native rule string, so `Finding::rule()` joins on `rules.external_id`, not a numeric FK.
- `routes/api.php` is loaded under the `web` middleware group with an `/api` prefix (see `bootstrap/app.php`) — session auth, CSRF-protected, no Sanctum.

---

## Teaching the model — the triage queue

`/triage` is the labelling workflow. It exists separately from the per-scan view because they answer different questions: a scan page asks *"what is wrong with this commit"*, the queue asks *"give me the next thing to judge"*.

It is **grouped by rule, across every scan**. Judging twenty `hardcoded-secret` findings in a row is faster and far more consistent than alternating between rule types, because you hold one set of criteria in mind at a time. The highest-volume rule is focused by default, so the biggest win is offered first.

| Key | Action |
|---|---|
| `J` / `↓` | next finding |
| `K` / `↑` | previous |
| `T` | true positive |
| `F` | false positive |
| `U` | undo last label |

Each rule shows concrete criteria for what makes it a true or false positive (`TriageGuidance`, keyed on CWE so it also covers findings ingested from external scanners). Decisions save optimistically — a round-trip per label makes a 200-item queue unbearable — and roll back if the server rejects one.

**Undo matters more than it looks.** Labelling at speed means occasional mistakes, and a wrong label is worse than no label: it teaches the classifier the opposite of the truth. `DELETE /api/findings/{id}/triage` removes the feedback row and recomputes the rule's false-positive rate, so retracting a decision leaves no residue in either the training set or the noise stats.

### Getting label quality right

- **Judge on the code, not on the score.** Before the first training run every finding renders as `n/a` rather than `0%`, deliberately: a confidence number from an untrained or badly-trained model anchors your judgement and corrupts the data you are collecting.
- **Both classes are required.** Training refuses to run on a single-class label set, because a model fitted on one class answers the same label at full confidence for everything.
- **Bulk-labelling a whole page is legitimate** when a rule is obviously noise in your codebase — that is a real judgement, and the rule-noise loop is built to act on it.
- **Never auto-label to reach the threshold.** The model would learn to reproduce the scanner's heuristic, making the ML layer an expensive no-op.

---

## Built-in scanner

The app ships its own PHP analyser, so it can produce findings rather than only ingest someone else's report. It writes SARIF and hands off to the normal ingestion pipeline, which means a locally scanned project and a report uploaded from CI take the identical path — one ingestion route, and a portable artifact left on disk.

```bash
php artisan sast:scan --dry-run          # every project with a source_path, report only
php artisan sast:scan ELP-Form --sync    # one project, processed inline
php artisan sast:scan --path=C:/code/app # ad-hoc directory
```

| Rule | CWE | Severity |
|---|---|---|
| `php.laravel.security.sql-injection` | 89 | HIGH |
| `php.security.command-injection` | 78 | CRITICAL |
| `php.security.unserialize-user-input` | 502 | CRITICAL |
| `php.security.path-traversal` | 22 | HIGH |
| `php.laravel.security.xss-unescaped-output` | 79 | MEDIUM |
| `php.laravel.security.mass-assignment` | 915 | MEDIUM |
| `php.security.weak-hashing` | 327 | LOW |
| `php.security.hardcoded-secret` | 798 | HIGH |

Rules are **syntactic, not a taint analysis** — they match shapes that are frequently vulnerable and accept that many hits will be false positives. That is the whole premise of this application: the ML layer exists to learn which shapes matter in a given codebase, so a consistently noisy rule is more useful here than a clever quiet one. `mass-assignment` and `weak-hashing` are included specifically because they generate false positives for the rule-noise loop to learn from.

Enable, disable or reorder rules in `config/sast.php` under `scanner.rules`; the scanner is constructed from that list in `AppServiceProvider`.

---

## Source workspaces

The app is deployed away from the code it analyses, so source is acquired per scan rather than assumed present. `SourceWorkspaceFactory` picks a provider:

| Provider | When it's used | Cleanup |
|---|---|---|
| `LocalPathWorkspace` | `projects.source_path` points at a readable directory, or a checkout is already cached under the workspace root | none — the directory belongs to someone else |
| `GitCloneWorkspace` | git is enabled and the project has a `vcs_repo_slug` | deletes the checkout, always |
| `NullWorkspace` | nothing else applies | nothing acquired |

`ProcessScanJob` releases the workspace in a `finally`, so an ephemeral checkout is removed whether the scan succeeded, failed, or threw mid-enrichment.

This is what makes the feature vector real. Without a workspace, `cyclomatic_complexity`, `has_sanitizer_in_ast`, `line_depth_in_function` and `developer_experience_lvl` all fall back to defaults — 4 of the 9 features. Verified against a live clone of `nikic/PHP-Parser`: complexity `10` and depth `21` where the defaults would have been `1` and `0`.

```bash
# Local development — no credentials needed
php artisan tinker --execute 'App\Models\Project::find(1)->update(["source_path" => "C:/path/to/repo"]);'

# Hosted — clone per scan
SAST_WORKSPACE_GIT_ENABLED=true
SAST_GIT_ALLOWED_HOSTS=github.com,gitlab.com
SAST_GIT_MAX_SIZE_MB=512
SAST_GIT_TIMEOUT_SECONDS=300
```

### Security posture

Cloning third-party code is untrusted input, so the git provider is deliberately narrow:

- **No arbitrary URLs.** The remote is *built* from an allowlisted host plus a strictly validated `owner/repo` slug, which removes the SSRF surface instead of trying to filter it. Slugs containing `..`, `;`, spaces or a scheme are rejected outright.
- **Tokens never reach argv.** Credentials go through `GIT_CONFIG_*` environment variables, so they don't appear in a process listing. Errors are redacted before logging.
- **Bounded.** `timeout_seconds` is a budget for the *whole* acquisition, not per git call, so a stalled fetch plus its fallback can't block a worker for double the limit. Oversized checkouts are discarded.
- **Cleanup can't wander.** `release()` refuses to delete any path whose basename isn't a `scan-*` scratch directory.

Static analysis never *executes* the fetched code, which removes the worst class of risk — but none of the above is optional in a multi-tenant deployment.

### Not yet implemented
- **Multi-tenancy.** `Project` has no owner, team, or org — every authenticated user sees every project. This is the main blocker before running it as a real SaaS, alongside per-tenant rate limiting and quota on clone size/frequency.
- **No archive upload provider.** Private repos with no network path from the app can't be scanned; only local paths and git clones are supported.
- `package.json` is missing the `lint:check` / `format:check` / `types:check` scripts (and their devDependencies) that `composer ci:check` invokes, so the npm half of CI cannot pass. Pint, PHPStan, and the test suite are all green.
- `Project` has no management UI — create projects via tinker or a seeder before uploading.
