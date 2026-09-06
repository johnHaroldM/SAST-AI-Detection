<?php

use App\Models\AiAssessment;
use App\Models\Finding;
use App\Models\Project;
use App\Models\Scan;
use App\Models\User;
use App\Services\Triage\FindingReport;
use App\Services\Triage\SuggestedFix;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

beforeEach(function () {
    $this->user = User::factory()->create();

    $this->root = storage_path('app/testing/report-'.Str::random(8));
    mkdir($this->root.'/app/Http/Controllers', 0755, true);

    config()->set('sast.workspace.root', $this->root);
    config()->set('sast.workspace.driver', 'local');

    $this->project = Project::factory()->create([
        'name' => 'Demo App',
        'source_path' => $this->root,
    ]);
});

afterEach(function () {
    if (isset($this->root) && is_dir($this->root)) {
        File::deleteDirectory($this->root);
    }
});

function writeControllerFixture(string $root): void
{
    file_put_contents($root.'/app/Http/Controllers/UploadController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class UploadController
{
    public function store($request)
    {
        $fileName = $request->input('fileName');
        $storagePath = storage_path('app/public/uploads/');

        $filePath = $storagePath . $fileName;
        file_put_contents($filePath, $request->file('upload')->get());

        return response()->json(['ok' => true]);
    }
}
PHP);
}

it('shows the real source around the flagged line', function () {
    writeControllerFixture($this->root);

    $finding = Finding::factory()->vectorized()->create([
        'scan_id' => Scan::factory()->for($this->project),
        'file_path' => 'app/Http/Controllers/UploadController.php',
        'line_number' => 13,
        'cwe_id' => 22,
        'raw_snippet' => 'file_put_contents($filePath, $request->file(\'upload\')->get());',
    ]);

    $report = app(FindingReport::class)->for($finding->fresh()->load('scan.project'));

    expect($report['code']['available'])->toBeTrue();

    $flagged = collect($report['code']['lines'])->firstWhere('flagged', true);

    expect($flagged['number'])->toBe(13)
        ->and($flagged['text'])->toContain('file_put_contents')
        // Surrounding context must be present, not just the one line.
        ->and(count($report['code']['lines']))->toBeGreaterThan(5);
});

it('reports which project and folder the finding belongs to', function () {
    // Several registered projects share paths like app/Http/Controllers/...,
    // so the report has to disambiguate.
    writeControllerFixture($this->root);

    $finding = Finding::factory()->vectorized()->create([
        'scan_id' => Scan::factory()->for($this->project),
        'file_path' => 'app/Http/Controllers/UploadController.php',
        'line_number' => 13,
        'cwe_id' => 22,
    ]);

    $location = app(FindingReport::class)->for($finding->fresh()->load('scan.project'))['location'];

    expect($location['project'])->toBe('Demo App')
        ->and($location['directory'])->toBe('app/Http/Controllers')
        ->and($location['file'])->toBe('UploadController.php')
        ->and($location['segments'])->toBe(['app', 'Http', 'Controllers'])
        ->and($location['absolute'])->toContain('UploadController.php');
});

it('degrades gracefully when the source is not on disk', function () {
    $finding = Finding::factory()->vectorized()->create([
        'scan_id' => Scan::factory()->for(Project::factory()->create(['source_path' => null])),
        'file_path' => 'app/Missing.php',
        'cwe_id' => 22,
    ]);

    $report = app(FindingReport::class)->for($finding->fresh()->load('scan.project'));

    expect($report['code']['available'])->toBeFalse()
        ->and($report['code']['reason'])->not->toBeEmpty()
        // The advice half must still be usable without the code.
        ->and($report['what']['risk'])->not->toBeEmpty()
        ->and($report['how']['summary'])->not->toBeEmpty();
});

it('structures the report as what, why, ai review and how', function () {
    $finding = Finding::factory()->vectorized()->create(['cwe_id' => 89]);

    $report = app(FindingReport::class)->for($finding->fresh()->load('scan.project'));

    expect($report)->toHaveKeys(['finding', 'location', 'what', 'why', 'aiReview', 'how', 'code'])
        ->and($report['what']['title'])->toBe('SQL injection')
        ->and($report['why'])->toHaveKeys(['detected', 'truePositive', 'falsePositive'])
        ->and($report['aiReview'])->toHaveKeys(['rubix_prediction', 'rubix_probability', 'reviewers'])
        ->and($report['how'])->toHaveKeys(['summary', 'suggestion', 'generic']);
});

it('explains each ai flag from the reviewer evidence and rubix prediction', function () {
    $scan = Scan::factory()->for($this->project)->create();
    $finding = Finding::factory()->for($scan)->scored('false_positive', 0.2)->create();

    AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => 'atake',
        'model' => 'test-atake',
        'classification' => 'likely_tp',
        'confidence' => 0.88,
        'attacker_controlled' => true,
        'sink_reachable' => true,
        'mitigation_detected' => false,
        'supporting_evidence' => ['User input reaches the file operation.'],
        'contradicting_evidence' => [],
        'preconditions' => ['The path is attacker controlled.'],
        'missing_evidence' => [],
        'remediation' => ['Resolve and validate the path.'],
        'reasoning_summary' => 'The sink is reachable without validation.',
        'prompt_version' => 'atake-v2',
        'completed_at' => now(),
    ]);

    AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => 'depensa',
        'model' => 'test-depensa',
        'classification' => 'likely_fp',
        'confidence' => 0.76,
        'attacker_controlled' => false,
        'sink_reachable' => true,
        'mitigation_detected' => true,
        'supporting_evidence' => [],
        'contradicting_evidence' => ['The path is reduced to a fixed basename.'],
        'preconditions' => [],
        'missing_evidence' => [],
        'remediation' => [],
        'reasoning_summary' => 'A path constraint blocks traversal.',
        'prompt_version' => 'depensa-v2',
        'completed_at' => now(),
    ]);

    $aiReview = app(FindingReport::class)->for($finding->fresh()->load('scan.project'))['aiReview'];

    expect($aiReview['rubix_prediction'])->toBe('false_positive')
        ->and($aiReview['reviewers'])->toHaveCount(2)
        ->and($aiReview['reviewers'][0]['reviewer'])->toBe('atake')
        ->and($aiReview['reviewers'][0]['evaluation_outcome'])->toBe('false_negative')
        ->and($aiReview['reviewers'][0]['outcome_reason'])->toContain('ATAKE found evidence')
        ->and($aiReview['reviewers'][0]['supporting_evidence'])->toContain('User input reaches the file operation.')
        ->and($aiReview['reviewers'][1]['reviewer'])->toBe('depensa')
        ->and($aiReview['reviewers'][1]['evaluation_outcome'])->toBe('true_negative')
        ->and($aiReview['reviewers'][1]['outcome_reason'])->toContain('DEPENSA agreed');
});

it('rewrites the developer\'s own line rather than a textbook example', function () {
    $finding = Finding::factory()->create([
        'cwe_id' => 22,
        'raw_snippet' => 'file_put_contents($filePath, $data);',
    ]);

    $fix = app(SuggestedFix::class)->for($finding);

    expect($fix['before'])->toBe('file_put_contents($filePath, $data);')
        // The rewrite must reference the developer's actual variable.
        ->and($fix['after'])->toContain('$filePath')
        ->and($fix['after'])->toContain('basename(')
        ->and($fix['note'])->not->toBeEmpty();
});

it('turns interpolated SQL into placeholders plus bindings', function () {
    $finding = Finding::factory()->create([
        'cwe_id' => 89,
        'raw_snippet' => 'DB::select("SELECT * FROM users WHERE id = $userId");',
    ]);

    $fix = app(SuggestedFix::class)->for($finding);

    expect($fix['after'])->toContain('?')
        ->and($fix['after'])->toContain('$userId');
});

it('warns that the weak-hash rewrite is only right for credentials', function () {
    // Swapping md5 for Hash::make in a cache key would break the cache, so the
    // suggestion must not read as unconditional.
    $finding = Finding::factory()->create([
        'cwe_id' => 327,
        'raw_snippet' => '$key = md5($path);',
    ]);

    expect(app(SuggestedFix::class)->for($finding)['note'])->toContain('cache key');
});

it('renders the report page', function () {
    writeControllerFixture($this->root);

    $finding = Finding::factory()->vectorized()->create([
        'scan_id' => Scan::factory()->for($this->project),
        'file_path' => 'app/Http/Controllers/UploadController.php',
        'line_number' => 13,
        'cwe_id' => 22,
        'raw_snippet' => 'file_put_contents($filePath, $data);',
    ]);

    $this->actingAs($this->user)
        ->get(route('findings.report', $finding))
        ->assertOk()
        ->assertInertia(fn ($page) => $page
            ->component('Findings/Report')
            ->where('what.title', 'Path traversal')
            ->where('location.project', 'Demo App')
            ->where('code.available', true)
            ->has('aiReview.reviewers', 2)
            ->has('how.suggestion.after')
        );
});

it('requires authentication to read a report', function () {
    $finding = Finding::factory()->create();

    $this->get(route('findings.report', $finding))->assertRedirect(route('login'));
});
