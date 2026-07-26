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

- The model pipeline uses Rubix ML and persists training artifacts via filesystem and/or Laravel jobs.
- The scan upload route is `GET /scans/upload` and is rendered by `App\Http\Controllers\Web\ScanDashboardController::create()`.
- The upload page posts scan reports to the existing `/api/scans` endpoint using `router.post` from Inertia.
- `resources/js/app.jsx` is the main Inertia entry point, resolving `.jsx` and `.tsx` page components.
- The frontend currently uses `@inertiajs/react` v2 and does not support `setLayoutProps` or `useHttp` exports.

## Current branch additions and changes

### CI/CD documentation

- Added `docs/ci.md` with explicit local commands and pipeline notes.
- Updated `README.md` with a CI/CD section and testing guidance.

### Workspace and branch status

- Working branch: `feature/add-upload-page`.
- The branch has been pushed to `origin/feature/add-upload-page`.
- The branch is currently ahead of remote by one commit containing the CI documentation updates.

### Tests

- Existing test coverage includes `tests/Feature/ScanUploadTest.php`.
- This test verifies authenticated users can view `/scans/upload` and guests are redirected to login.
- No new functional feature tests were added beyond the existing scan upload test.

## How to use this document

1. Read this file before making changes or answering questions.
2. If a requested feature is not listed here, do not assume it exists.
3. Refer to actual files in the codebase for implementation details.
4. When updating the project, add a clear `docs/scope/CHANGELOG.md` entry if behavior or scope changes.
