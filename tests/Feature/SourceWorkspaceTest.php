<?php

use App\Jobs\ProcessScanJob;
use App\Models\Finding;
use App\Models\Project;
use App\Models\Scan;
use App\Services\AI\FindingContextBuilder;
use App\Services\FeatureVectorBuilder;
use App\Services\RubixTriageService;
use App\Services\ScannerReportParsers\ReportParserFactory;
use App\Services\Workspaces\GitCloneWorkspace;
use App\Services\Workspaces\LocalPathWorkspace;
use App\Services\Workspaces\NullWorkspace;
use App\Services\Workspaces\SourceWorkspaceFactory;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

/**
 * The workspace layer is what lets a hosted deployment analyse code that
 * lives somewhere else. These cover provider selection, the safety limits on
 * cloning untrusted repositories, and — most importantly — that AST features
 * actually come alive once real source is present.
 */
beforeEach(function () {
    $this->root = storage_path('app/testing/workspaces-'.Str::random(8));
    mkdir($this->root, 0755, true);

    config()->set('sast.workspace.root', $this->root);
    config()->set('sast.workspace.driver', 'auto');
    config()->set('sast.workspace.git.enabled', false);
});

afterEach(function () {
    if (isset($this->root) && is_dir($this->root)) {
        File::deleteDirectory($this->root);
    }
});
/** Writes a small PHP file with known AST characteristics. */
function writeSourceFile(string $dir, string $relative, string $contents): string
{
    $full = $dir.'/'.$relative;
    @mkdir(dirname($full), 0755, true);
    file_put_contents($full, $contents);

    return $full;
}

it('prefers an explicit project source path over everything else', function () {
    $source = $this->root.'/my-working-copy';
    mkdir($source, 0755, true);

    $project = Project::factory()->create(['source_path' => $source]);
    $scan = Scan::factory()->for($project)->create();

    $workspace = app(SourceWorkspaceFactory::class)->for($scan);

    expect($workspace)->toBeInstanceOf(LocalPathWorkspace::class)
        ->and($workspace->isAvailable())->toBeTrue()
        ->and($workspace->path())->toBe($source)
        ->and($workspace->driver())->toBe('local');
});

it('falls back to a cached checkout in the workspace root', function () {
    $project = Project::factory()->create(['source_path' => null]);
    $scan = Scan::factory()->for($project)->create();

    $cached = $this->root.'/'.$project->id.'/'.$scan->commit_sha;
    mkdir($cached, 0755, true);

    $workspace = app(SourceWorkspaceFactory::class)->for($scan);

    expect($workspace->isAvailable())->toBeTrue()
        ->and($workspace->path())->toBe($cached);
});

it('returns an unavailable workspace when no source can be obtained', function () {
    $project = Project::factory()->create(['source_path' => null, 'vcs_repo_slug' => null]);
    $scan = Scan::factory()->for($project)->create();

    $workspace = app(SourceWorkspaceFactory::class)->for($scan);

    expect($workspace)->toBeInstanceOf(NullWorkspace::class)
        ->and($workspace->isAvailable())->toBeFalse()
        ->and($workspace->driver())->toBe('none');
});

it('never touches the network when the driver is local', function () {
    config()->set('sast.workspace.driver', 'local');
    config()->set('sast.workspace.git.enabled', true);

    $project = Project::factory()->create([
        'source_path' => null,
        'vcs_repo_slug' => 'acme/should-never-be-cloned',
    ]);
    $scan = Scan::factory()->for($project)->create();

    expect(app(SourceWorkspaceFactory::class)->for($scan))->toBeInstanceOf(NullWorkspace::class);
});

it('does not clone when git support is switched off', function () {
    config()->set('sast.workspace.git.enabled', false);

    $project = Project::factory()->create([
        'source_path' => null,
        'vcs_repo_slug' => 'acme/demo',
    ]);
    $scan = Scan::factory()->for($project)->create();

    expect(app(SourceWorkspaceFactory::class)->for($scan))->toBeInstanceOf(NullWorkspace::class);
});

it('refuses to clone from a host outside the allowlist', function () {
    // SSRF guard: a project pointing at an internal host must never be dialled.
    config()->set('sast.workspace.git.enabled', true);
    config()->set('sast.workspace.git.allowed_hosts', ['github.com']);

    $project = Project::factory()->create([
        'source_path' => null,
        'vcs_repo_slug' => 'acme/demo',
        'vcs_host' => '169.254.169.254',
    ]);
    $scan = Scan::factory()->for($project)->create();

    expect(app(SourceWorkspaceFactory::class)->for($scan))->toBeInstanceOf(NullWorkspace::class);
});

it('rejects repository slugs that could smuggle arguments or traverse paths', function (string $slug) {
    $workspace = new GitCloneWorkspace(
        scratchPath: $this->root.'/scan-should-not-exist',
        host: 'github.com',
        repoSlug: $slug,
        commitSha: str_repeat('a', 40),
        branch: 'main',
        accessToken: null,
    );

    expect($workspace->acquire())->toBeFalse()
        ->and($workspace->isAvailable())->toBeFalse()
        ->and(is_dir($this->root.'/scan-should-not-exist'))->toBeFalse();
})->with([
    '../../etc/passwd',
    'acme/demo --upload-pack=touch',
    'acme/demo;rm -rf /',
    'https://evil.test/acme/demo',
    'acme',
    '',
]);

it('deletes an ephemeral checkout on release', function () {
    $scratch = $this->root.'/scan-1-abcdef-XYZ123';
    mkdir($scratch.'/nested', 0755, true);
    file_put_contents($scratch.'/nested/file.php', '<?php echo 1;');

    $workspace = new GitCloneWorkspace(
        scratchPath: $scratch,
        host: 'github.com',
        repoSlug: 'acme/demo',
        commitSha: str_repeat('a', 40),
        branch: 'main',
        accessToken: null,
    );

    $workspace->release();

    expect(is_dir($scratch))->toBeFalse();
});

it('refuses to delete a path that is not a scan scratch directory', function () {
    // Cleanup must never be able to wander outside the scratch area.
    $precious = $this->root.'/someones-working-copy';
    mkdir($precious, 0755, true);
    file_put_contents($precious.'/important.php', '<?php // do not delete');

    $workspace = new GitCloneWorkspace(
        scratchPath: $precious,
        host: 'github.com',
        repoSlug: 'acme/demo',
        commitSha: null,
        branch: 'main',
        accessToken: null,
    );

    $workspace->release();

    expect(is_dir($precious))->toBeTrue()
        ->and(file_exists($precious.'/important.php'))->toBeTrue();
});

it('fully deletes a deep tree containing read-only files', function () {
    // Regression: deleting while recursively iterating made the iterator skip
    // entries, so real checkouts (a .git dir full of read-only pack files)
    // were only partially removed and leaked disk on every scan.
    $scratch = $this->root.'/scan-7-cafebabe-DEEP01';

    foreach (['a/b/c', 'a/b/d', '.git/objects/ab', '.git/refs/heads'] as $dir) {
        mkdir($scratch.'/'.$dir, 0755, true);
    }

    foreach (['a/b/c/one.php', 'a/b/d/two.php', '.git/objects/ab/pack', '.git/refs/heads/main', 'root.php'] as $file) {
        file_put_contents($scratch.'/'.$file, 'x');
    }

    // Git leaves object files read-only; unlink fails on Windows unless the
    // attribute is cleared first.
    chmod($scratch.'/.git/objects/ab/pack', 0444);

    (new GitCloneWorkspace(
        scratchPath: $scratch,
        host: 'github.com',
        repoSlug: 'acme/demo',
        commitSha: null,
        branch: 'main',
        accessToken: null,
    ))->release();

    expect(is_dir($scratch))->toBeFalse();
});

it('treats the timeout as a budget for the whole acquisition', function () {
    // A stalled fetch that then falls back to a branch fetch must not be able
    // to block a queue worker for twice the configured limit.
    $workspace = new GitCloneWorkspace(
        scratchPath: $this->root.'/scan-8-budget-BUD001',
        host: 'github.com',
        repoSlug: 'acme/demo',
        commitSha: str_repeat('a', 40),
        branch: 'main',
        accessToken: null,
        gitBinary: 'git',
        timeoutSeconds: 2,
    );

    $started = microtime(true);
    $workspace->acquire();
    $elapsed = microtime(true) - $started;

    // Generous ceiling — the point is that it is bounded by roughly one
    // budget, not two, plus process spawn overhead.
    expect($elapsed)->toBeLessThan(12.0);

    $workspace->release();
});

it('generates scratch paths that stay inside the workspace root', function () {
    $path = GitCloneWorkspace::scratchPathFor($this->root, 42, str_repeat('f', 40));

    expect($path)->toStartWith($this->root)
        ->and(basename($path))->toStartWith('scan-42-');
});

it('is safe to release more than once', function () {
    $scratch = $this->root.'/scan-9-deadbeef-AAA111';
    mkdir($scratch, 0755, true);

    $workspace = new GitCloneWorkspace(
        scratchPath: $scratch,
        host: 'github.com',
        repoSlug: 'acme/demo',
        commitSha: null,
        branch: 'main',
        accessToken: null,
    );

    $workspace->release();
    $workspace->release();

    expect(is_dir($scratch))->toBeFalse();
});

it('extracts real AST features once source is actually available', function () {
    // This is the payoff: with a workspace, cyclomatic_complexity,
    // has_sanitizer_in_ast and line_depth_in_function stop being defaults.
    Storage::fake('local');

    $source = $this->root.'/checkout';
    mkdir($source, 0755, true);

    writeSourceFile($source, 'app/Http/Controllers/OrderController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function search($request)
    {
        $term = $request->input('q');

        if ($term === null) {
            return [];
        }

        foreach ($this->sources() as $source) {
            if ($source->enabled && $source->ready) {
                $safe = htmlspecialchars($term);
                $rows = $this->query($safe);
            }
        }

        return $rows ?? [];
    }
}
PHP);

    $project = Project::factory()->create(['source_path' => $source]);
    $scan = Scan::factory()->for($project)->create();

    $report = json_encode([
        'version' => '2.1.0',
        'runs' => [[
            'tool' => ['driver' => ['rules' => [[
                'id' => 'php.security.sqli',
                'properties' => ['tags' => ['CWE-89']],
            ]]]],
            'results' => [[
                'ruleId' => 'php.security.sqli',
                'level' => 'error',
                'message' => ['text' => 'Untrusted input reaches a query'],
                'locations' => [['physicalLocation' => [
                    'artifactLocation' => ['uri' => 'app/Http/Controllers/OrderController.php'],
                    'region' => ['startLine' => 20],
                ]]],
            ]],
        ]],
    ]);

    Storage::disk('local')->put($scan->raw_report_path, $report);

    app(ProcessScanJob::class, ['scan' => $scan])->handle(
        app(ReportParserFactory::class),
        app(FeatureVectorBuilder::class),
        app(RubixTriageService::class),
        app(SourceWorkspaceFactory::class),
        app(FindingContextBuilder::class),
    );
    $vector = Finding::sole()->feature_vector;

    expect($vector['cyclomatic_complexity'])->toBeGreaterThan(1)
        ->and($vector['has_sanitizer_in_ast'])->toBe(1)
        ->and($vector['line_depth_in_function'])->toBeGreaterThan(0)
        ->and($vector['file_extension'])->toBe('php');
});

it('still ingests when the workspace is unavailable, using default features', function () {
    Storage::fake('local');

    $project = Project::factory()->create(['source_path' => null, 'vcs_repo_slug' => null]);
    $scan = Scan::factory()->for($project)->create();

    $report = json_encode([
        'version' => '2.1.0',
        'runs' => [[
            'tool' => ['driver' => ['rules' => []]],
            'results' => [[
                'ruleId' => 'php.security.sqli',
                'level' => 'error',
                'message' => ['text' => 'Untrusted input reaches a query'],
                'locations' => [['physicalLocation' => [
                    'artifactLocation' => ['uri' => 'app/Missing.php'],
                    'region' => ['startLine' => 12],
                ]]],
            ]],
        ]],
    ]);

    Storage::disk('local')->put($scan->raw_report_path, $report);

    app(ProcessScanJob::class, ['scan' => $scan])->handle(
        app(ReportParserFactory::class),
        app(FeatureVectorBuilder::class),
        app(RubixTriageService::class),
        app(SourceWorkspaceFactory::class),
        app(FindingContextBuilder::class),
    );

    $vector = Finding::sole()->feature_vector;

    expect($scan->fresh()->status)->toBe('complete')
        ->and($vector['cyclomatic_complexity'])->toBe(1)
        ->and($vector['has_sanitizer_in_ast'])->toBe(0);
});
