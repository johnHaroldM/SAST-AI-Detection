# CI / CD Documentation

This repository uses GitHub Actions to validate code on every push to `main` and on pull requests.

## Workflow

The workflow is defined in `.github/workflows/tests.yml`.

It performs the following steps:

1. Checkout the repository.
2. Setup PHP 8.5 with Composer.
3. Setup Node 22.
4. Run `composer setup` to install PHP dependencies, configure the environment, run database migrations, and build frontend assets.
5. Run `composer ci:check` to perform linting, type checking, and tests.

## Local commands

To mirror CI locally, run:

```bash
composer setup
composer ci:check
composer test
php artisan test --filter=ScanUploadTest --compact
npm run build
```

## Scan upload coverage

The scan upload page is covered by `tests/Feature/ScanUploadTest.php`.
It verifies that authenticated users can view `/scans/upload` and guests are redirected to login.

## Notes

- `composer setup` may create a local `.env` file and run `php artisan migrate --force`.
- The repo currently expects `@inertiajs/react`, Laravel Fortify, and existing auth middleware to be configured.
- If the pipeline needs expansion, add dedicated browser or API integration jobs in `.github/workflows/`.
