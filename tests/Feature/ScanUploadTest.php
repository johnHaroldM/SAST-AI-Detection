<?php

use App\Jobs\AnalyzeFindingsWithAninoJob;
use App\Models\AiAssessment;
use App\Models\AninoAnalysisRun;
use App\Models\Finding;
use App\Models\FindingAiContext;
use App\Models\Project;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Support\Facades\Queue;
use Inertia\Testing\AssertableInertia as Assert;

beforeEach(function () {
    $this->user = User::factory()->create();
    $this->project = Project::factory()->create();
});

test('authenticated users can view the scan upload page', function () {
    $this->actingAs($this->user);

    $this->get(route('scans.create'))
        ->assertOk()
        ->assertInertia(fn (Assert $page) => $page
            ->component('Scans/Upload')
            ->where('projects', fn ($projects) => count($projects) === 1 && $projects[0]['id'] === $this->project->id)
        );
});

test('guests are redirected from the scan upload page', function () {
    $response = $this->get(route('scans.create'));

    $response->assertRedirect(route('login'));
});

test('disabled anino analysis does not queue reviewers', function () {
    Queue::fake();
    config()->set('services.ollama.enabled', false);

    $scan = Scan::factory()->for($this->project)->create();

    $this->actingAs($this->user)
        ->post(route('scans.anino.analyze', $scan))
        ->assertRedirect()
        ->assertSessionHas('error');

    Queue::assertNotPushed(AnalyzeFindingsWithAninoJob::class);
});

test('enabled anino analysis queues reviewers for scans with ai context', function () {
    Queue::fake();
    config()->set('services.ollama.enabled', true);

    $scan = Scan::factory()->for($this->project)->create();
    $finding = Finding::factory()->for($scan)->create();

    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'context'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);

    $this->actingAs($this->user)
        ->post(route('scans.anino.analyze', $scan))
        ->assertRedirect()
        ->assertSessionHas('success');

    Queue::assertPushed(AnalyzeFindingsWithAninoJob::class);
});

test('enabled anino analysis backfills missing ai context before queueing reviewers', function () {
    Queue::fake();
    config()->set('services.ollama.enabled', true);

    $scan = Scan::factory()->for($this->project)->create();
    Finding::factory()->for($scan)->create();

    $this->actingAs($this->user)
        ->post(route('scans.anino.analyze', $scan))
        ->assertRedirect()
        ->assertSessionHas('success');

    expect(FindingAiContext::count())->toBe(1);
    Queue::assertPushed(AnalyzeFindingsWithAninoJob::class);
});

test('anino analysis queues only the configured high risk slice', function () {
    Queue::fake();
    config()->set('services.ollama.enabled', true);
    config()->set('services.ollama.max_findings_per_run', 2);

    $scan = Scan::factory()->for($this->project)->create();
    Finding::factory()->count(3)->for($scan)->create();

    $this->actingAs($this->user)
        ->post(route('scans.anino.analyze', $scan))
        ->assertRedirect()
        ->assertSessionHas('success');

    expect(FindingAiContext::count())->toBe(3)
        ->and(AninoAnalysisRun::sole()->total_findings)->toBe(2);

    Queue::assertPushed(AnalyzeFindingsWithAninoJob::class);
});

test('anino analysis does not queue duplicate active review runs', function () {
    Queue::fake();
    config()->set('services.ollama.enabled', true);

    $scan = Scan::factory()->for($this->project)->create();
    $finding = Finding::factory()->for($scan)->create();

    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'context'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);

    AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'running',
        'phase' => 'depensa',
        'total_findings' => 10,
        'reviewed_findings' => 1,
        'heartbeat_at' => now(),
    ]);
    AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'skipped',
        'phase' => 'locked',
        'total_findings' => 10,
        'last_error' => 'Another ATAKE/DEPENSA review is already running for this scan.',
        'heartbeat_at' => now(),
        'completed_at' => now(),
    ]);

    $this->actingAs($this->user)
        ->post(route('scans.anino.analyze', $scan))
        ->assertRedirect()
        ->assertSessionHas('error');

    expect(AninoAnalysisRun::count())->toBe(2);
    Queue::assertNotPushed(AnalyzeFindingsWithAninoJob::class);
});

test('anino retry queues only failed findings from the previous run', function () {
    Queue::fake();
    config()->set('services.ollama.enabled', true);

    $scan = Scan::factory()->for($this->project)->create();
    $findings = Finding::factory()->count(3)->for($scan)->create();

    foreach ($findings as $finding) {
        FindingAiContext::create([
            'finding_id' => $finding->id,
            'source_commit' => $scan->commit_sha,
            'context_hash' => hash('sha256', 'context-'.$finding->id),
            'metadata' => [],
            'context' => 'scanner evidence',
        ]);
    }

    AiAssessment::create([
        'finding_id' => $findings[0]->id,
        'reviewer' => 'adjudicator',
        'model' => 'deterministic-rules-v1',
        'classification' => 'likely_tp',
        'confidence' => 0.9,
        'prompt_version' => 'rules-v1',
        'completed_at' => now(),
    ]);

    AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'complete_with_errors',
        'phase' => 'complete',
        'candidate_finding_ids' => [$findings[0]->id, $findings[1]->id],
        'total_findings' => 2,
        'processed_findings' => 2,
        'reviewed_findings' => 1,
        'failed_findings' => 1,
        'heartbeat_at' => now(),
        'completed_at' => now(),
    ]);

    $this->actingAs($this->user)
        ->post(route('scans.anino.analyze', $scan))
        ->assertRedirect()
        ->assertSessionHas('success');

    $retry = AninoAnalysisRun::query()->latest('id')->firstOrFail();

    expect($retry->candidate_finding_ids)->toBe([$findings[1]->id])
        ->and($retry->total_findings)->toBe(1);

    Queue::assertPushed(
        AnalyzeFindingsWithAninoJob::class,
        fn (AnalyzeFindingsWithAninoJob $job) => $job->runId === $retry->id,
    );
});
