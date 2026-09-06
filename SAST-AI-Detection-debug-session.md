# SAST-AI-Detection Debugging Session Recap

## Repository
`johnHaroldM/SAST-AI-Detection`

## Goal
Get the feature branch / PR CI pipeline passing by fixing environment, formatting, static analysis, and test failures.

---

## 1. CI failed because `.env.example` was missing

### Error
```text
Run cp .env.example .env
cp: cannot stat '.env.example': No such file or directory
Error: Process completed with exit code 1.
```

### Cause
The feature branch had deleted `.env.example`, while the GitHub Actions workflow still ran:

```bash
cp .env.example .env
php artisan key:generate
```

### Fix
Restore `.env.example` from `main`:

```bash
git fetch origin
git switch feat-AI-ATAKE-DEPENSA
git restore --source=origin/main -- .env.example
git add .env.example
git commit -m "fix(ci): restore .env.example"
git push origin feat-AI-ATAKE-DEPENSA
```

---

## 2. Laravel Pint failed on `FindingContextBuilder.php`

### Error
```text
FAIL ... 157 files, 1 style issue
app/Services/AI/FindingContextBuilder.php
new_with_parentheses, no_multiline_whitespace_around_double_arrow
```

### Fixes

Change:

```php
new SecretRedactor()
```

to:

```php
new SecretRedactor
```

And change multiline `=>` values like:

```php
'rubix_tp_probability' =>
    $finding->tp_probability,
```

to:

```php
'rubix_tp_probability' => $finding->tp_probability,
```

Likewise for:

```php
'rubix_predicted_label' => $finding->predicted_label,
```

### Result
```powershell
vendor/bin/pint --test --parallel
```

Output:

```text
PASS ... 157 files
```

---

## 3. PHPStan initially crashed because of low PHP memory

### Error
```text
PHPStan process crashed because it reached configured PHP memory limit: 128M
```

### Fix
Run PHPStan with a higher memory limit:

```powershell
vendor/bin/phpstan analyse --no-progress --memory-limit=1G
```

---

## 4. PHPStan found 2 real type errors

### Error 1
```text
app\Jobs\AnalyzeFindingsWithAninoJob.php

Method AnalyzeFindingsWithAninoJob::storeAssessment()
has parameter $review with no value type specified in iterable type array.
```

### Fix
Add a PHPDoc array shape directly above `storeAssessment()`:

```php
/**
 * @param array{
 *     reviewer: string,
 *     model: string,
 *     prompt_version: string,
 *     result: array<string, mixed>,
 *     usage: array<string, mixed>,
 *     raw: array<string, mixed>
 * } $review
 */
private function storeAssessment(Finding $finding, array $review): void
{
    // ...
}
```

### Error 2
```text
app\Services\AI\AiAssessmentSchema.php

Method AiAssessmentSchema::make()
return type has no value type specified in iterable type array.
```

### Initial mistake
The PHPDoc was placed above the class:

```php
/**
 * @return array<string, mixed>
 */
final class AiAssessmentSchema
```

That does not document the return type of `make()`.

### Correct fix
Move the PHPDoc directly above the method:

```php
final class AiAssessmentSchema
{
    /**
     * @return array<string, mixed>
     */
    public static function make(): array
    {
        // ...
    }
}
```

### Result
```powershell
vendor/bin/phpstan analyse --no-progress --memory-limit=1G
```

Output:

```text
[OK] No errors
```

---

## 5. Laravel tests initially failed because SQLite PDO was disabled

### Error
```text
could not find driver
(Connection: sqlite, Database: :memory:)
```

### Environment check
```powershell
php --ini
```

Output showed:

```text
Loaded Configuration File: C:\PHP\php.ini
```

And:

```powershell
php -m | Select-String -Pattern "sqlite|pdo"
```

Initially showed only:

```text
PDO
pdo_mysql
```

### Fix in `C:\PHP\php.ini`
Enable:

```ini
extension=pdo_sqlite
extension=sqlite3
```

Also ensure:

```ini
extension_dir = "ext"
```

### Verification
After enabling SQLite:

```powershell
php -m | Select-String -Pattern "sqlite|pdo"
```

Output:

```text
PDO
pdo_mysql
pdo_sqlite
sqlite3
```

### PowerShell-safe SQLite check
Use:

```powershell
php -r "new PDO('sqlite::memory:'); echo 'SQLite OK', PHP_EOL;"
```

Do not use the previous quoting form that caused:

```text
PHP Parse error: unexpected token ":"
```

---

## 6. Test suite then ran successfully enough to expose real failures

### Result
```text
Tests: 7 failed, 158 passed (685 assertions)
```

The recurring Windows message:

```text
'rm' is not recognized as an internal or external command
```

is a separate cross-platform cleanup issue.

---

## 7. Remaining 7 test failures: `ProcessScanJob::handle()` now needs a 5th dependency

### Error
```text
Too few arguments to function App\Jobs\ProcessScanJob::handle(),
4 passed ... and exactly 5 expected
```

Current method signature includes:

```php
FindingContextBuilder $aiContextBuilder
```

The tests still invoke `handle()` manually with only 4 dependencies.

### Affected tests
At least:

```text
tests/Feature/ScanIngestionPipelineTest.php
tests/Feature/SourceWorkspaceTest.php
```

### Fix
Add:

```php
use App\Services\AI\FindingContextBuilder;
```

Then change calls from:

```php
$job->handle(
    app(ReportParserFactory::class),
    app(FeatureVectorBuilder::class),
    app(RubixTriageService::class),
    app(SourceWorkspaceFactory::class),
);
```

to:

```php
$job->handle(
    app(ReportParserFactory::class),
    app(FeatureVectorBuilder::class),
    app(RubixTriageService::class),
    app(SourceWorkspaceFactory::class),
    app(FindingContextBuilder::class),
);
```

Also update the exception assertion:

```php
expect(fn () => $job->handle(
    app(ReportParserFactory::class),
    app(FeatureVectorBuilder::class),
    app(RubixTriageService::class),
    app(SourceWorkspaceFactory::class),
    app(FindingContextBuilder::class),
))->toThrow(JsonException::class);
```

The JSON test was failing with `ArgumentCountError` only because execution never reached the parser.

### Find all stale calls
```powershell
Get-ChildItem tests -Recurse -Filter *.php |
    Select-String -Pattern "SourceWorkspaceFactory::class"
```

---

## 8. Windows portability issue: `rm`

The test output repeatedly showed:

```text
'rm' is not recognized as an internal or external command
```

### Find the source
```powershell
Get-ChildItem app,tests -Recurse -Filter *.php |
    Select-String -Pattern "rm -|rm "
```

### Better cross-platform approach
Avoid shelling out to:

```php
exec('rm -rf ...');
```

Prefer Laravel / PHP filesystem APIs, for example:

```php
use Illuminate\Support\Facades\File;

File::deleteDirectory($path);
```

This is not the cause of the current 7 failing tests, but it should be cleaned up for Windows compatibility.

---

# Current Status

```text
✅ .env.example restored
✅ Pint passes
✅ PHPStan passes with --memory-limit=1G
✅ SQLite PDO enabled locally
✅ 158 tests passing
🔧 7 tests failing because ProcessScanJob::handle() test calls need FindingContextBuilder
⚠️ Windows "rm" portability issue remains
⬜ Re-run full test suite
⬜ Run SAST self-scan
⬜ Commit and push
```

---

# Recommended Next Commands

After updating the test calls:

```powershell
vendor/bin/pint
vendor/bin/pint --test --parallel
vendor/bin/phpstan analyse --no-progress --memory-limit=1G
php artisan test --compact
```

If the test suite passes, run:

```powershell
php artisan sast:inspect app --format=sarif --output=self-scan.sarif.json --fail-on=CRITICAL
```

Then:

```powershell
git status
git add .
git commit -m "fix: resolve CI formatting, static analysis, and test issues"
git push
```

---

# Notes

- Do not commit local `php.ini` changes.
- The SQLite fix is local machine configuration only.
- The `--memory-limit=1G` flag is for local PHPStan execution because the local PHP CLI was configured with `128M`.
- The remaining test failures are application/test-code mismatches caused by adding `FindingContextBuilder` to `ProcessScanJob::handle()`.
