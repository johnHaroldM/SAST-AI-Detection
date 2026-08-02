<?php

use App\Jobs\PostPrCommentsJob;
use App\Jobs\ProcessScanJob;
use App\Models\Finding;
use App\Models\Project;
use App\Models\Rule;
use App\Models\Scan;
use App\Models\User;
use App\Services\FeatureVectorBuilder;
use App\Services\RubixTriageService;
use App\Services\ScannerReportParsers\ReportParserFactory;
use App\Services\Workspaces\SourceWorkspaceFactory;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

/**
 * Covers ingestion end to end: upload -> parse -> feature vectors -> the
 * point where findings are labelable training data.
 */
beforeEach(function () {
    Storage::fake('local');

    $this->user = User::factory()->create();
    $this->project = Project::factory()->create();

    config()->set('sast.training.model_path', 'testing/'.Str::uuid().'.rbx');
});

function sarifReport(int $results = 3): string
{
    $items = collect(range(1, $results))->map(fn (int $i) => [
        'ruleId' => "php.security.rule-{$i}",
        'level' => 'error',
        'message' => ['text' => "Possible SQL injection at call site {$i}"],
        'locations' => [[
            'physicalLocation' => [
                'artifactLocation' => ['uri' => "app/Http/Controllers/Controller{$i}.php"],
                'region' => ['startLine' => 10 + $i, 'snippet' => ['text' => 'DB::raw($input);']],
            ],
        ]],
    ])->all();

    return json_encode([
        'version' => '2.1.0',
        'runs' => [[
            'tool' => ['driver' => ['rules' => collect(range(1, $results))->map(fn (int $i) => [
                'id' => "php.security.rule-{$i}",
                'properties' => ['tags' => ['security', 'CWE-89']],
            ])->all()]],
            'results' => $items,
        ]],
    ]);
}

it('accepts an upload and queues the ingestion pipeline', function () {
    Queue::fake();

    $this->actingAs($this->user)
        ->post(route('scans.store'), [
            'project_id' => $this->project->id,
            'source' => 'sarif',
            'commit_sha' => str_repeat('a', 40),
            'branch' => 'main',
            'report' => UploadedFile::fake()->createWithContent('report.json', sarifReport()),
        ])
        ->assertRedirect()
        ->assertSessionHas('success');

    $scan = Scan::sole();

    expect($scan->status)->toBe('uploaded')
        ->and($scan->project_id)->toBe($this->project->id);

    Storage::disk('local')->assertExists($scan->raw_report_path);
    Queue::assertPushed(ProcessScanJob::class);
});

it('rejects a malformed commit sha', function () {
    $this->actingAs($this->user)
        ->post(route('scans.store'), [
            'project_id' => $this->project->id,
            'source' => 'sarif',
            'commit_sha' => 'not-a-sha',
            'branch' => 'main',
            'report' => UploadedFile::fake()->createWithContent('report.json', sarifReport()),
        ])
        ->assertSessionHasErrors('commit_sha');

    expect(Scan::count())->toBe(0);
});

it('requires authentication to upload', function () {
    $this->post(route('scans.store'), [])->assertRedirect(route('login'));
});

it('parses a report into findings with feature vectors', function () {
    $scan = Scan::factory()->for($this->project)->create();
    Storage::disk('local')->put($scan->raw_report_path, sarifReport(3));

    app(ProcessScanJob::class, ['scan' => $scan])->handle(
        app(ReportParserFactory::class),
        app(FeatureVectorBuilder::class),
        app(RubixTriageService::class),
        app(SourceWorkspaceFactory::class),
    );

    $scan->refresh();

    expect($scan->status)->toBe('complete')
        ->and($scan->total_findings)->toBe(3)
        ->and(Finding::count())->toBe(3);

    $finding = Finding::first();

    expect($finding->feature_vector)->toBeArray()
        ->toHaveKeys([
            'cwe_id', 'scanner_severity', 'file_extension', 'is_test_file',
            'cyclomatic_complexity', 'has_sanitizer_in_ast', 'line_depth_in_function',
            'historical_fp_rate_rule', 'developer_experience_lvl',
        ])
        ->and($finding->cwe_id)->toBe(89)
        ->and($finding->severity)->toBe('HIGH');
});

it('completes ingestion without a trained model and leaves findings unscored', function () {
    // The cold-start case: without this, the very first scan can never be
    // ingested, so there is never any data to train the first model on.
    $scan = Scan::factory()->for($this->project)->create();
    Storage::disk('local')->put($scan->raw_report_path, sarifReport(2));

    app(ProcessScanJob::class, ['scan' => $scan])->handle(
        app(ReportParserFactory::class),
        app(FeatureVectorBuilder::class),
        app(RubixTriageService::class),
        app(SourceWorkspaceFactory::class),
    );

    expect($scan->fresh()->status)->toBe('complete')
        ->and(Finding::count())->toBe(2)
        ->and(Finding::whereNotNull('predicted_label')->count())->toBe(0)
        ->and(Finding::where('status', 'pending')->count())->toBe(2);
});

it('registers each distinct scanner rule exactly once per scan', function () {
    $scan = Scan::factory()->for($this->project)->create();
    Storage::disk('local')->put($scan->raw_report_path, sarifReport(3));

    app(ProcessScanJob::class, ['scan' => $scan])->handle(
        app(ReportParserFactory::class),
        app(FeatureVectorBuilder::class),
        app(RubixTriageService::class),
        app(SourceWorkspaceFactory::class),
    );

    expect(Rule::count())->toBe(3)
        ->and(Rule::pluck('external_id')->all())->toContain('php.security.rule-1');
});

it('does not queue PR comments when nothing was scored', function () {
    Queue::fake();

    $scan = Scan::factory()->for($this->project)->create();
    Storage::disk('local')->put($scan->raw_report_path, sarifReport(2));

    app(ProcessScanJob::class, ['scan' => $scan])->handle(
        app(ReportParserFactory::class),
        app(FeatureVectorBuilder::class),
        app(RubixTriageService::class),
        app(SourceWorkspaceFactory::class),
    );

    Queue::assertNotPushed(PostPrCommentsJob::class);
});

it('marks the scan failed when the report cannot be parsed', function () {
    $scan = Scan::factory()->for($this->project)->create();
    Storage::disk('local')->put($scan->raw_report_path, 'this is not json');

    expect(fn () => app(ProcessScanJob::class, ['scan' => $scan])->handle(
        app(ReportParserFactory::class),
        app(FeatureVectorBuilder::class),
        app(RubixTriageService::class),
        app(SourceWorkspaceFactory::class),
    ))->toThrow(JsonException::class);

    expect($scan->fresh()->status)->toBe('failed');
});

it('links findings to their rule through the scanner rule identifier', function () {
    $rule = Rule::factory()->create(['external_id' => 'php.security.sqli']);
    $finding = Finding::factory()->create(['rule_id' => 'php.security.sqli']);

    // findings.rule_id is a string, not a numeric FK — this relation is
    // what feeds historical_fp_rate_rule back into the feature vector.
    expect($finding->rule)->not->toBeNull()
        ->and($finding->rule->id)->toBe($rule->id)
        ->and($rule->findings)->toHaveCount(1);
});
