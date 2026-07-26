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
| `app/Services/RubixTriageService.php` | **Core ML engine**: vectorize → OneHotEncoder → ZScaleStandardizer → RandomForest → predict/train, with precision/recall/F1 scoring | Phase 2 & 3 |
| `app/Console/Commands/TrainSastModelCommand.php` | `php artisan sast:train` | Phase 2 |
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

### Not yet implemented
- Auth scaffolding (`routes/web.php` assumes `auth`/`verified` middleware from your existing setup — Breeze/Fortify/Jetstream, whichever you're using).
- Scan upload form (currently upload-only via the API; a drag-and-drop `Scans/Create.jsx` would be a natural next addition).
- `ModelState` history page for the precision/recall trend line mentioned in the `ModelState` model docblock.
