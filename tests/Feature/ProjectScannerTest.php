<?php

use App\Services\Scanner\ProjectScanner;
use App\Services\Scanner\SarifReportWriter;
use App\Services\ScannerReportParsers\SarifReportParser;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

/**
 * The scanner is deliberately syntactic, so these tests pin down two things:
 * that the vulnerable shapes are caught, and — just as important — that the
 * safe equivalents stay quiet. A rule that fires on everything teaches the
 * triage model nothing.
 */
beforeEach(function () {
    $this->root = storage_path('app/testing/scan-'.Str::random(8));
    mkdir($this->root.'/app', 0755, true);
});

afterEach(function () {
    if (isset($this->root) && is_dir($this->root)) {
        File::deleteDirectory($this->root);
    }
});

function sourceFile(string $root, string $name, string $php): void
{
    file_put_contents($root.'/app/'.$name, "<?php\n".$php);
}

/** @return list<string> rule ids that fired */
function scanIds(string $root): array
{
    return array_map(
        fn ($f) => $f->ruleId,
        app(ProjectScanner::class)->scan($root)
    );
}

it('flags SQL built by concatenation', function () {
    sourceFile($this->root, 'A.php', '
        class A {
            public function run($request) {
                return DB::select("SELECT * FROM users WHERE id = " . $request->id);
            }
        }');

    expect(scanIds($this->root))->toContain('php.laravel.security.sql-injection');
});

it('stays quiet on a fully literal query', function () {
    sourceFile($this->root, 'A.php', '
        class A {
            public function run() {
                return DB::select("SELECT * FROM users WHERE active = 1");
            }
        }');

    expect(scanIds($this->root))->not->toContain('php.laravel.security.sql-injection');
});

it('flags shell execution built from input', function () {
    sourceFile($this->root, 'B.php', '
        class B {
            public function run($file) { return shell_exec("convert " . $file); }
        }');

    expect(scanIds($this->root))->toContain('php.security.command-injection');
});

it('flags backtick execution', function () {
    sourceFile($this->root, 'B.php', 'class B { public function r() { return `ls -la`; } }');

    expect(scanIds($this->root))->toContain('php.security.command-injection');
});

it('flags unserialize on request input', function () {
    sourceFile($this->root, 'C.php', '
        class C {
            public function run($request) { return unserialize($request->input("payload")); }
        }');

    expect(scanIds($this->root))->toContain('php.security.unserialize-user-input');
});

it('flags dynamic include but not a literal one', function () {
    sourceFile($this->root, 'D.php', 'class D { public function r($p) { include $p; } }');
    sourceFile($this->root, 'E.php', 'class E { public function r() { include "config.php"; } }');

    $ids = scanIds($this->root);

    expect($ids)->toContain('php.security.path-traversal')
        ->and(array_count_values($ids)['php.security.path-traversal'])->toBe(1);
});

it('flags unescaped echo but not an escaped one', function () {
    sourceFile($this->root, 'F.php', 'class F { public function r($n) { echo $n; } }');
    sourceFile($this->root, 'G.php', 'class G { public function r($n) { echo e($n); } }');
    sourceFile($this->root, 'H.php', 'class H { public function r($n) { echo htmlspecialchars($n); } }');

    $ids = scanIds($this->root);

    expect(array_count_values($ids)['php.laravel.security.xss-unescaped-output'] ?? 0)->toBe(1);
});

it('flags mass assignment from request input only', function () {
    sourceFile($this->root, 'I.php', '
        class I {
            public function bad($request) { return User::create($request->all()); }
            public function good($request) { return User::create(["name" => $request->name]); }
        }');

    $ids = scanIds($this->root);

    expect(array_count_values($ids)['php.laravel.security.mass-assignment'] ?? 0)->toBe(1);
});

it('flags weak hashing', function () {
    sourceFile($this->root, 'J.php', 'class J { public function r($password) { return md5($password); } }');

    expect(scanIds($this->root))->toContain('php.security.weak-hashing');
});

it('flags a hardcoded secret but ignores placeholders and short values', function () {
    sourceFile($this->root, 'K.php', '
        class K {
            public function r() {
                $api_key = "sk-live-9f83nfu2b8vd0193ndkq";
                $password = "";
                $token = "changeme";
                $secret = "abc";
            }
        }');

    $ids = scanIds($this->root);

    expect(array_count_values($ids)['php.security.hardcoded-secret'] ?? 0)->toBe(1);
});

it('does not mistake validation rules or error messages for credentials', function () {
    // These two shapes made the rule almost pure noise in Laravel codebases:
    // a credential-sounding key holding a validator string or prose.
    sourceFile($this->root, 'V.php', '
        class V {
            public function rules() {
                return [
                    "password" => "required|string|min:6|confirmed",
                    "current_password" => "required|min:8",
                    "api_token" => "nullable|string|max:255",
                ];
            }
            public function messages() {
                return ["current_password" => "The current password is incorrect."];
            }
        }');

    expect(scanIds($this->root))->not->toContain('php.security.hardcoded-secret');
});

it('ignores excluded directories', function () {
    mkdir($this->root.'/vendor/pkg', 0755, true);
    file_put_contents(
        $this->root.'/vendor/pkg/Bad.php',
        '<?php class Bad { public function r($x) { return shell_exec($x); } }'
    );

    expect(scanIds($this->root))->toBeEmpty();
});

it('records unparseable files instead of failing the scan', function () {
    sourceFile($this->root, 'Good.php', 'class Good { public function r($x) { return unserialize($x); } }');
    file_put_contents($this->root.'/app/Broken.php', '<?php class Broken { this is not php ###');

    $scanner = app(ProjectScanner::class);
    $findings = $scanner->scan($this->root);

    expect($findings)->toHaveCount(1)
        ->and($scanner->skippedFiles())->toHaveCount(1)
        ->and($scanner->filesScanned())->toBe(1);
});

it('reports paths relative to the project root', function () {
    sourceFile($this->root, 'L.php', 'class L { public function r($x) { return unserialize($x); } }');

    $finding = app(ProjectScanner::class)->scan($this->root)[0];

    expect($finding->filePath)->toBe('app/L.php')
        ->and($finding->lineNumber)->toBeGreaterThan(0)
        ->and($finding->snippet)->toContain('unserialize');
});

it('survives a round trip through SARIF without losing severity or CWE', function () {
    // CRITICAL has no SARIF `level` equivalent, so it must ride in properties
    // or every critical finding silently downgrades to HIGH on ingest.
    sourceFile($this->root, 'M.php', 'class M { public function r($x) { return unserialize($x); } }');

    $rules = array_map(fn (string $r) => app($r), (array) config('sast.scanner.rules'));
    $findings = app(ProjectScanner::class)->scan($this->root);

    $sarif = app(SarifReportWriter::class)->toJson($findings, $rules);
    $reparsed = (new SarifReportParser)->parse($sarif);

    expect($reparsed)->toHaveCount(1)
        ->and($reparsed[0]->severity)->toBe('CRITICAL')
        ->and($reparsed[0]->cweId)->toBe(502)
        ->and($reparsed[0]->ruleId)->toBe('php.security.unserialize-user-input')
        ->and($reparsed[0]->filePath)->toBe('app/M.php');
});

it('produces valid SARIF 2.1.0 structure', function () {
    sourceFile($this->root, 'N.php', 'class N { public function r($x) { return unserialize($x); } }');

    $rules = array_map(fn (string $r) => app($r), (array) config('sast.scanner.rules'));
    $document = app(SarifReportWriter::class)->toArray(
        app(ProjectScanner::class)->scan($this->root),
        $rules
    );

    expect($document['version'])->toBe('2.1.0')
        ->and($document['runs'][0]['tool']['driver']['rules'])->toHaveCount(count($rules))
        ->and($document['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'])
        ->toBe('app/N.php');
});

it('returns nothing for a directory that does not exist', function () {
    expect(app(ProjectScanner::class)->scan($this->root.'/nope'))->toBeEmpty();
});
