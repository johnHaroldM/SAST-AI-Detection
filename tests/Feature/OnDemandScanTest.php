<?php

use App\Exceptions\LocalScanNotPermittedException;
use App\Models\Finding;
use App\Models\Project;
use App\Models\Scan;
use App\Models\User;
use App\Services\Scanner\LocalScanGuard;
use App\Services\Scanner\OnDemandScanner;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

beforeEach(function () {
    $this->user = User::factory()->create();

    $this->root = storage_path('app/testing/ondemand-'.Str::random(8));
    mkdir($this->root.'/app', 0755, true);

    config()->set('sast.scanner.local_scan.enabled', true);
    config()->set('sast.scanner.local_scan.allowed_roots', []);
    config()->set('sast.workspace.driver', 'local');
    config()->set('sast.training.model_path', 'testing/'.Str::uuid().'.rbx');
});

afterEach(function () {
    if (isset($this->root) && is_dir($this->root)) {
        File::deleteDirectory($this->root);
    }
});

it('scans and ingests in one invocation', function () {
    file_put_contents(
        $this->root.'/app/Vuln.php',
        '<?php class V { public function r($request) { return unserialize($request->input("p")); } }'
    );

    $project = Project::factory()->create(['source_path' => $this->root]);

    $result = app(OnDemandScanner::class)->scan($project);

    expect($result['findings'])->toBeGreaterThan(0)
        ->and($result['files'])->toBeGreaterThan(0)
        ->and($result['scan']->status)->toBe('complete');

    // Findings are ingested and vectorised, not merely written to a report.
    expect(Finding::count())->toBe($result['findings'])
        ->and(Finding::whereNotNull('feature_vector')->count())->toBe($result['findings']);
});

it('records a working-tree branch when the directory is not a git checkout', function () {
    file_put_contents($this->root.'/app/A.php', '<?php class A { function r($x) { return unserialize($x); } }');

    $project = Project::factory()->create(['source_path' => $this->root]);
    $scan = app(OnDemandScanner::class)->scan($project)['scan'];

    expect($scan->branch)->toBe('working-tree')
        ->and($scan->commit_sha)->toHaveLength(40);
});

it('refuses to scan when local scanning is switched off', function () {
    // Reading an arbitrary directory and rendering it back is an
    // arbitrary-file-read primitive on a shared host.
    config()->set('sast.scanner.local_scan.enabled', false);

    app(LocalScanGuard::class)->assertScannable($this->root);
})->throws(LocalScanNotPermittedException::class, 'disabled');

it('refuses a path outside the configured roots', function () {
    config()->set('sast.scanner.local_scan.allowed_roots', [storage_path('app/testing/somewhere-else')]);

    app(LocalScanGuard::class)->assertScannable($this->root);
})->throws(LocalScanNotPermittedException::class, 'outside the directories');

it('accepts a path inside the configured roots', function () {
    config()->set('sast.scanner.local_scan.allowed_roots', [storage_path('app/testing')]);

    expect(app(LocalScanGuard::class)->assertScannable($this->root))->toContain('ondemand-');
});

it('rejects a traversal that resolves outside an allowed root', function () {
    config()->set('sast.scanner.local_scan.allowed_roots', [$this->root]);

    app(LocalScanGuard::class)->assertScannable($this->root.'/../../..');
})->throws(LocalScanNotPermittedException::class);

it('refuses a directory that does not exist', function () {
    app(LocalScanGuard::class)->assertScannable($this->root.'/nope');
})->throws(LocalScanNotPermittedException::class, 'Not a readable directory');

it('registers a project from the UI', function () {
    $this->actingAs($this->user)
        ->post(route('projects.store'), [
            'name' => 'Checkout API',
            'source_path' => $this->root,
        ])
        ->assertRedirect(route('projects.index'))
        ->assertSessionHas('success');

    expect(Project::where('name', 'Checkout API')->exists())->toBeTrue();
});

it('rejects a source path that does not exist', function () {
    // A bad path would otherwise create a project that silently never scans.
    $this->actingAs($this->user)
        ->post(route('projects.store'), [
            'name' => 'Ghost',
            'source_path' => $this->root.'/not-here',
        ])
        ->assertSessionHasErrors('source_path');

    expect(Project::count())->toBe(0);
});

it('rejects a malformed repository slug', function () {
    $this->actingAs($this->user)
        ->post(route('projects.store'), ['name' => 'X', 'vcs_repo_slug' => 'not a slug'])
        ->assertSessionHasErrors('vcs_repo_slug');
});

it('scans from the UI and lands on the results', function () {
    file_put_contents($this->root.'/app/Vuln.php', '<?php class V { function r($x) { return unserialize($x); } }');

    $project = Project::factory()->create(['source_path' => $this->root]);

    $this->actingAs($this->user)
        ->post(route('projects.scan', $project))
        ->assertRedirect()
        ->assertSessionHas('success');

    expect(Scan::where('project_id', $project->id)->where('status', 'complete')->exists())->toBeTrue();
});

it('reports a clean scan without pretending there are results', function () {
    file_put_contents($this->root.'/app/Safe.php', '<?php class S { function r() { return 1 + 1; } }');

    $project = Project::factory()->create(['source_path' => $this->root]);

    $this->actingAs($this->user)
        ->post(route('projects.scan', $project))
        ->assertRedirect(route('projects.index'))
        ->assertSessionHas('success');

    expect(Finding::count())->toBe(0);
});

it('surfaces a refusal as an error rather than a crash', function () {
    config()->set('sast.scanner.local_scan.enabled', false);

    $project = Project::factory()->create(['source_path' => $this->root]);

    $this->actingAs($this->user)
        ->post(route('projects.scan', $project))
        ->assertRedirect()
        ->assertSessionHas('error');
});

it('requires authentication to register or scan', function () {
    $project = Project::factory()->create(['source_path' => $this->root]);

    $this->post(route('projects.store'), ['name' => 'X'])->assertRedirect(route('login'));
    $this->post(route('projects.scan', $project))->assertRedirect(route('login'));
});
