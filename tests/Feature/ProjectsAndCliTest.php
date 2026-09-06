<?php

use App\Models\Finding;
use App\Models\Project;
use App\Models\Scan;
use App\Models\User;
use App\Services\Scanner\ScanTargetInspector;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

beforeEach(function () {
    $this->user = User::factory()->create();

    $this->root = storage_path('app/testing/proj-'.Str::random(8));
    mkdir($this->root.'/app/Http', 0755, true);
    mkdir($this->root.'/vendor/acme', 0755, true);
    mkdir($this->root.'/tests', 0755, true);

    file_put_contents($this->root.'/app/Http/Controller.php', '<?php class C {}');
    file_put_contents($this->root.'/app/Model.php', '<?php class M {}');
    file_put_contents($this->root.'/tests/Test.php', '<?php class T {}');
    file_put_contents($this->root.'/vendor/acme/Vendor.php', '<?php class V {}');
});

afterEach(function () {
    if (isset($this->root) && is_dir($this->root)) {
        File::deleteDirectory($this->root);
    }
});

it('reports which directories are in scope and which are excluded', function () {
    // An excluded directory looks identical to one with no findings unless
    // the boundary is stated explicitly.
    $project = Project::factory()->create(['source_path' => $this->root]);

    $target = app(ScanTargetInspector::class)->inspect($project);

    expect($target['readable'])->toBeTrue();

    $byName = collect($target['directories'])->keyBy('name');

    expect($byName['app']['included'])->toBeTrue()
        ->and($byName['app']['php_files'])->toBe(2)
        ->and($byName['tests']['included'])->toBeTrue()
        ->and($byName['vendor']['included'])->toBeFalse()
        ->and($byName['vendor']['php_files'])->toBe(0)
        ->and($target['excluded_directories'])->toContain('vendor');
});

it('marks a project unreadable when its source path is gone', function () {
    $project = Project::factory()->create(['source_path' => $this->root.'/does-not-exist']);

    expect(app(ScanTargetInspector::class)->inspect($project)['readable'])->toBeFalse();
});

it('handles a project with no source path at all', function () {
    $project = Project::factory()->create(['source_path' => null]);

    $target = app(ScanTargetInspector::class)->inspect($project);

    expect($target['readable'])->toBeFalse()
        ->and($target['directories'])->toBeEmpty();
});

it('lists every project with its tree and finding counts', function () {
    $project = Project::factory()->create(['name' => 'Alpha', 'source_path' => $this->root]);
    $scan = Scan::factory()->for($project)->create();

    Finding::factory()->count(3)->vectorized()->create(['scan_id' => $scan->id]);
    Finding::factory()->labeled('true_positive')->create(['scan_id' => $scan->id]);

    $this->actingAs($this->user)
        ->get(route('projects.index'))
        ->assertOk()
        ->assertInertia(fn ($page) => $page
            ->component('Projects/Index')
            ->where('projects.0.name', 'Alpha')
            ->where('projects.0.findings.total', 4)
            ->where('projects.0.findings.pending', 3)
            ->where('projects.0.findings.true_positive', 1)
            ->where('projects.0.target.readable', true)
            ->has('excludedByConfig')
        );
});

it('requires authentication to view projects', function () {
    $this->get(route('projects.index'))->assertRedirect(route('login'));
});

it('scans a directory from the CLI without touching the database', function () {
    file_put_contents($this->root.'/app/Vuln.php', '<?php class V { function r($x) { return unserialize($x); } }');

    $this->artisan('sast:inspect', ['path' => $this->root, '--format' => 'json', '--quiet-summary' => true])
        ->assertExitCode(0);

    // The standalone command is for build agents with no app database.
    expect(Scan::count())->toBe(0)
        ->and(Finding::count())->toBe(0);
});

it('fails the build when a finding meets the severity gate', function () {
    file_put_contents($this->root.'/app/Vuln.php', '<?php class V { function r($x) { return unserialize($x); } }');

    // unserialize() on a dynamic value is CRITICAL.
    $this->artisan('sast:inspect', [
        'path' => $this->root,
        '--format' => 'json',
        '--fail-on' => 'CRITICAL',
        '--quiet-summary' => true,
    ])->assertExitCode(1);
});

it('passes the gate when nothing reaches the threshold', function () {
    $this->artisan('sast:inspect', [
        'path' => $this->root,
        '--format' => 'json',
        '--fail-on' => 'CRITICAL',
        '--quiet-summary' => true,
    ])->assertExitCode(0);
});

it('writes a SARIF report to the requested file', function () {
    file_put_contents($this->root.'/app/Vuln.php', '<?php class V { function r($x) { return unserialize($x); } }');
    $out = $this->root.'/results.sarif';

    $this->artisan('sast:inspect', [
        'path' => $this->root,
        '--format' => 'sarif',
        '--output' => $out,
        '--quiet-summary' => true,
    ])->assertExitCode(0);

    $sarif = json_decode((string) file_get_contents($out), true);

    expect($sarif['version'])->toBe('2.1.0')
        ->and($sarif['runs'][0]['results'])->not->toBeEmpty();
});

it('rejects a path that is not a directory', function () {
    $this->artisan('sast:inspect', ['path' => $this->root.'/nope'])->assertExitCode(1);
});
