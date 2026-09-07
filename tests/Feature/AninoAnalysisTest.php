<?php

use App\Jobs\AnalyzeFindingsWithAninoJob;
use App\Jobs\TrainSastModelJob;
use App\Models\AiAssessment;
use App\Models\AiAssessmentFeedback;
use App\Models\AninoAnalysisRun;
use App\Models\Finding;
use App\Models\FindingAiContext;
use App\Models\Scan;
use App\Models\TriageFeedback;
use App\Models\User;
use App\Services\AI\AiAssessmentSchema;
use App\Services\AI\AiEvaluationOutcome;
use App\Services\AI\AninoCandidateSelector;
use App\Services\AI\AninoRunManager;
use App\Services\AI\AtakeReviewer;
use App\Services\AI\DepensaReviewer;
use App\Services\AI\FindingAdjudicator;
use App\Services\AI\OllamaClient;
use App\Services\AI\OllamaUnavailableException;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;

test('anino percent confidence is normalized before storage', function () {
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->scored('true_positive')->create();

    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'scanner evidence'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);

    $review = [
        'reviewer' => 'depensa',
        'model' => 'test-model',
        'prompt_version' => 'depensa-v1',
        'result' => [
            'classification' => 'likely_fp',
            'confidence' => 50,
            'attacker_controlled' => true,
            'sink_reachable' => true,
            'mitigation_detected' => false,
            'preconditions' => [],
            'supporting_evidence' => [],
            'contradicting_evidence' => [],
            'missing_evidence' => [],
            'remediation' => [],
            'reasoning_summary' => 'Needs more evidence.',
        ],
        'usage' => [],
        'raw' => [],
    ];

    $method = new ReflectionMethod(AnalyzeFindingsWithAninoJob::class, 'storeAssessment');
    $method->invoke(new AnalyzeFindingsWithAninoJob($scan->id), $finding, $review);

    expect(AiAssessment::sole()->confidence)->toBe(0.5)
        ->and(AiAssessment::sole()->evaluation_outcome)->toBe('false_positive');
});

test('anino preserves reviewed assessment history when the input context changes', function () {
    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->create();
    $context = FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'old scanner evidence'),
        'metadata' => [],
        'context' => 'old scanner evidence',
    ]);
    $oldAssessment = AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => 'atake',
        'model' => 'test-model',
        'classification' => 'confirmed_fp',
        'prompt_version' => AtakeReviewer::PROMPT_VERSION,
        'context_hash' => $context->context_hash,
        'completed_at' => now()->subMinute(),
    ]);
    AiAssessmentFeedback::create([
        'assessment_id' => $oldAssessment->id,
        'user_id' => $user->id,
        'verdict' => 'correct',
        'reviewed_at' => now()->subMinute(),
    ]);

    $context->update([
        'context_hash' => hash('sha256', 'new scanner evidence'),
        'context' => 'new scanner evidence',
    ]);
    $finding->unsetRelation('aiContext');

    $method = new ReflectionMethod(AnalyzeFindingsWithAninoJob::class, 'storeAssessment');
    $method->invoke(
        new AnalyzeFindingsWithAninoJob($scan->id),
        $finding,
        aninoReview('atake', 'test-model'),
    );

    expect(AiAssessment::where('finding_id', $finding->id)->where('reviewer', 'atake')->count())->toBe(2)
        ->and($oldAssessment->fresh()->classification)->toBe('confirmed_fp')
        ->and($oldAssessment->fresh()->feedback)->toHaveCount(1)
        ->and(AiAssessment::query()->latest('id')->firstOrFail()->context_hash)->toBe($context->fresh()->context_hash);
});

test('anino requeues a finding when its evidence context changes', function () {
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->create(['severity' => 'CRITICAL']);
    $context = FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'old scanner evidence'),
        'metadata' => [],
        'context' => 'old scanner evidence',
    ]);

    AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => 'adjudicator',
        'model' => 'deterministic-rules-v1',
        'classification' => 'needs_validation',
        'prompt_version' => 'adjudicator-v1',
        'context_hash' => $context->context_hash,
        'completed_at' => now(),
    ]);

    expect(app(AninoCandidateSelector::class)->forScan($scan)->all())->toBeEmpty();

    $context->update([
        'context_hash' => hash('sha256', 'source-backed evidence'),
        'context' => 'source-backed evidence',
    ]);

    expect(app(AninoCandidateSelector::class)->forScan($scan)->all())->toBe([$finding->id]);
});

test('ai reviews are compared with rubix predictions as confusion matrix outcomes', function () {
    expect(AiEvaluationOutcome::classify('true_positive', 'likely_tp'))->toBe('true_positive')
        ->and(AiEvaluationOutcome::classify('true_positive', 'confirmed_fp'))->toBe('false_positive')
        ->and(AiEvaluationOutcome::classify('false_positive', 'likely_fp'))->toBe('true_negative')
        ->and(AiEvaluationOutcome::classify('false_positive', 'confirmed_tp'))->toBe('false_negative')
        ->and(AiEvaluationOutcome::classify('true_positive', 'needs_validation'))->toBe('unresolved')
        ->and(AiEvaluationOutcome::classify(null, 'likely_tp'))->toBe('unresolved');
});

test('scan anino status reports reviewer progress and recent logs', function () {
    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->scored('true_positive')->create();

    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'scanner evidence'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);

    AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => 'atake',
        'model' => 'test-model',
        'classification' => 'likely_tp',
        'confidence' => 0.75,
        'preconditions' => [],
        'supporting_evidence' => [],
        'contradicting_evidence' => [],
        'missing_evidence' => [],
        'remediation' => [],
        'reasoning_summary' => 'Looks reachable.',
        'prompt_version' => AtakeReviewer::PROMPT_VERSION,
        'completed_at' => now(),
    ]);

    $this->actingAs($user)
        ->getJson(route('api.scans.anino-status', $scan))
        ->assertOk()
        ->assertJsonPath('total_findings', 1)
        ->assertJsonPath('contexts', 1)
        ->assertJsonPath('atake', 1)
        ->assertJsonPath('depensa', 0)
        ->assertJsonPath('outcomes.atake.true_positive', 1)
        ->assertJsonPath('outcomes.atake.false_positive', 0)
        ->assertJsonPath('outcomes.depensa.true_positive', 0)
        ->assertJsonFragment([
            'message' => 'ATAKE completed finding #'.$finding->id,
        ]);
});

test('errored terminal runs expose retryable findings without a moving eta', function () {
    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->create();

    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'scanner evidence'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);

    AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'complete_with_errors',
        'phase' => 'complete',
        'candidate_finding_ids' => [$finding->id],
        'total_findings' => 1,
        'processed_findings' => 1,
        'failed_findings' => 1,
        'heartbeat_at' => now(),
        'completed_at' => now(),
    ]);

    $this->actingAs($user)
        ->getJson(route('api.scans.anino-status', $scan))
        ->assertOk()
        ->assertJsonPath('complete', true)
        ->assertJsonPath('retryable_findings', 1)
        ->assertJsonPath('run.estimated_remaining_seconds', 0);
});

test('scan page exposes an outcome flag for historical ai assessments', function () {
    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->scored('false_positive', 0.2)->create();

    AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => 'depensa',
        'model' => 'test-model',
        'classification' => 'confirmed_tp',
        'confidence' => 0.9,
        'prompt_version' => 'depensa-v1',
        'completed_at' => now(),
    ]);

    $this->actingAs($user)
        ->get(route('scans.show', $scan))
        ->assertOk()
        ->assertInertia(fn ($page) => $page
            ->component('Scans/Show')
            ->where('findings.data.0.ai_assessments.0.evaluation_outcome', 'false_negative')
        );
});

test('anino lock skips duplicate runs with a clear status', function () {
    $scan = Scan::factory()->create();
    AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'running',
        'phase' => 'atake',
        'total_findings' => 10,
        'heartbeat_at' => now(),
    ]);
    $run = AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'queued',
        'phase' => 'queued',
        'total_findings' => 10,
        'heartbeat_at' => now(),
    ]);
    $lock = Cache::lock("anino-analysis-run:{$scan->id}", 60);

    expect($lock->get())->toBeTrue();

    try {
        (new AnalyzeFindingsWithAninoJob($scan->id, $run->id))->handle(
            app(AtakeReviewer::class),
            app(DepensaReviewer::class),
            app(FindingAdjudicator::class),
            app(AninoCandidateSelector::class),
            app(OllamaClient::class),
        );
    } finally {
        $lock->release();
    }

    $run->refresh();

    expect($run->status)->toBe('skipped')
        ->and($run->phase)->toBe('locked')
        ->and($run->last_error)->toContain('already running');
});

test('stale anino runs release abandoned locks and can be restarted', function () {
    config()->set('services.ollama.stale_after', 120);
    $scan = Scan::factory()->create();
    $run = AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'running',
        'phase' => 'depensa',
        'total_findings' => 1,
        'heartbeat_at' => now()->subMinutes(10),
    ]);
    $lock = Cache::lock("anino-analysis-run:{$scan->id}", 600);
    expect($lock->get())->toBeTrue();

    expect(app(AninoRunManager::class)->active($scan))->toBeNull()
        ->and($run->fresh()->status)->toBe('failed')
        ->and($run->fresh()->phase)->toBe('stalled');

    $replacement = Cache::lock("anino-analysis-run:{$scan->id}", 10);
    expect($replacement->get())->toBeTrue();
    $replacement->release();
});

test('anino runs one reviewer per job in model-major order and unloads at phase boundaries', function () {
    Queue::fake();
    config()->set('services.ollama.models.atake', 'test-atake');
    config()->set('services.ollama.models.depensa', 'test-depensa');

    $scan = Scan::factory()->create();
    $findings = Finding::factory()->count(2)->for($scan)->create();

    foreach ($findings as $finding) {
        FindingAiContext::create([
            'finding_id' => $finding->id,
            'source_commit' => $scan->commit_sha,
            'context_hash' => hash('sha256', 'context-'.$finding->id),
            'metadata' => [],
            'context' => 'scanner evidence',
        ]);
    }

    $run = AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'queued',
        'phase' => 'queued',
        'candidate_finding_ids' => $findings->pluck('id')->all(),
        'total_findings' => 2,
        'heartbeat_at' => now(),
    ]);
    $atake = Mockery::mock(AtakeReviewer::class);
    $depensa = Mockery::mock(DepensaReviewer::class);
    $ollama = Mockery::mock(OllamaClient::class);
    $atake->shouldReceive('review')
        ->once()
        ->ordered()
        ->with(Mockery::on(fn (Finding $reviewed) => $reviewed->id === $findings[0]->id), '5m')
        ->andReturn(aninoReview('atake', 'test-atake'));
    $atake->shouldReceive('review')
        ->once()
        ->ordered()
        ->with(Mockery::on(fn (Finding $reviewed) => $reviewed->id === $findings[1]->id), '5m')
        ->andReturn(aninoReview('atake', 'test-atake'));
    $ollama->shouldReceive('unload')->once()->ordered()->with('test-atake');
    $depensa->shouldReceive('review')
        ->once()
        ->ordered()
        ->with(Mockery::on(fn (Finding $reviewed) => $reviewed->id === $findings[0]->id), '5m')
        ->andReturn(aninoReview('depensa', 'test-depensa'));
    $depensa->shouldReceive('review')
        ->once()
        ->ordered()
        ->with(Mockery::on(fn (Finding $reviewed) => $reviewed->id === $findings[1]->id), '5m')
        ->andReturn(aninoReview('depensa', 'test-depensa'));
    $ollama->shouldReceive('unload')->once()->ordered()->with('test-depensa');

    $runStep = function () use ($scan, $run, $atake, $depensa, $ollama): void {
        (new AnalyzeFindingsWithAninoJob($scan->id, $run->id))->handle(
            $atake,
            $depensa,
            app(FindingAdjudicator::class),
            app(AninoCandidateSelector::class),
            $ollama,
        );
    };

    $runStep();

    $run->refresh();

    expect($run->next_step)->toBe(1)
        ->and($run->processed_findings)->toBe(0)
        ->and($run->status)->toBe('running')
        ->and(AiAssessment::where('finding_id', $findings[0]->id)->where('reviewer', 'atake')->count())->toBe(1)
        ->and(AiAssessment::where('finding_id', $findings[1]->id)->count())->toBe(0);

    $runStep();
    expect($run->fresh()->next_step)->toBe(2)
        ->and($run->fresh()->phase)->toBe('depensa')
        ->and(AiAssessment::where('reviewer', 'atake')->count())->toBe(2)
        ->and(AiAssessment::where('reviewer', 'depensa')->count())->toBe(0);

    $runStep();
    expect($run->fresh()->next_step)->toBe(3)
        ->and($run->fresh()->processed_findings)->toBe(1)
        ->and($run->fresh()->reviewed_findings)->toBe(1)
        ->and(AiAssessment::where('finding_id', $findings[0]->id)->count())->toBe(3)
        ->and(AiAssessment::where('finding_id', $findings[1]->id)->count())->toBe(1);

    $runStep();
    expect($run->fresh()->next_step)->toBe(4)
        ->and($run->fresh()->status)->toBe('complete')
        ->and($run->fresh()->processed_findings)->toBe(2)
        ->and($run->fresh()->reviewed_findings)->toBe(2)
        ->and($run->fresh()->failed_findings)->toBe(0)
        ->and(AiAssessment::count())->toBe(6);

    Queue::assertPushed(AnalyzeFindingsWithAninoJob::class, 3);
});

test('anino advances a reused reviewer step and resumes with the missing reviewer only', function () {
    Queue::fake();
    config()->set('services.ollama.models.atake', 'test-atake');
    config()->set('services.ollama.models.depensa', 'test-depensa');

    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->create();
    $context = FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'context'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);
    AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => 'atake',
        'model' => 'test-atake',
        'classification' => 'likely_tp',
        'confidence' => 0.8,
        'prompt_version' => AtakeReviewer::PROMPT_VERSION,
        'context_hash' => $context->context_hash,
        'completed_at' => now(),
    ]);
    $run = AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'queued',
        'phase' => 'queued',
        'candidate_finding_ids' => [$finding->id],
        'total_findings' => 1,
        'heartbeat_at' => now(),
    ]);
    $atake = Mockery::mock(AtakeReviewer::class);
    $depensa = Mockery::mock(DepensaReviewer::class);
    $ollama = Mockery::mock(OllamaClient::class);
    $atake->shouldNotReceive('review');
    $depensa->shouldReceive('review')
        ->once()
        ->with(Mockery::on(fn (Finding $reviewed) => $reviewed->id === $finding->id), '5m')
        ->andReturn(aninoReview('depensa', 'test-depensa'));
    $ollama->shouldReceive('unload')->once()->with('test-atake');
    $ollama->shouldReceive('unload')->once()->with('test-depensa');

    (new AnalyzeFindingsWithAninoJob($scan->id, $run->id))->handle(
        $atake,
        $depensa,
        app(FindingAdjudicator::class),
        app(AninoCandidateSelector::class),
        $ollama,
    );

    expect($run->fresh()->status)->toBe('running')
        ->and($run->fresh()->next_step)->toBe(1)
        ->and($run->fresh()->processed_findings)->toBe(0)
        ->and(AiAssessment::where('finding_id', $finding->id)->where('reviewer', 'depensa')->exists())->toBeFalse();

    (new AnalyzeFindingsWithAninoJob($scan->id, $run->id))->handle(
        $atake,
        $depensa,
        app(FindingAdjudicator::class),
        app(AninoCandidateSelector::class),
        $ollama,
    );

    expect($run->fresh()->status)->toBe('complete')
        ->and($run->fresh()->next_step)->toBe(2)
        ->and($run->fresh()->processed_findings)->toBe(1)
        ->and(AiAssessment::where('finding_id', $finding->id)->where('reviewer', 'atake')->count())->toBe(1)
        ->and(AiAssessment::where('finding_id', $finding->id)->where('reviewer', 'adjudicator')->exists())->toBeTrue();
});

test('anino advances a structured reviewer failure and reports terminal finding counts', function () {
    Queue::fake();
    config()->set('services.ollama.models.atake', 'test-atake');
    config()->set('services.ollama.models.depensa', 'test-depensa');

    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->create();
    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'context'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);
    $run = AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'queued',
        'phase' => 'queued',
        'candidate_finding_ids' => [$finding->id],
        'total_findings' => 1,
        'heartbeat_at' => now(),
    ]);
    $atake = Mockery::mock(AtakeReviewer::class);
    $depensa = Mockery::mock(DepensaReviewer::class);
    $ollama = Mockery::mock(OllamaClient::class);
    $atake->shouldReceive('review')->once()->andThrow(new RuntimeException('Invalid structured output.'));
    $depensa->shouldReceive('review')->once()->andReturn(aninoReview('depensa', 'test-depensa'));
    $ollama->shouldReceive('unload')->once()->with('test-atake');
    $ollama->shouldReceive('unload')->once()->with('test-depensa');

    foreach (range(1, 2) as $_) {
        (new AnalyzeFindingsWithAninoJob($scan->id, $run->id))->handle(
            $atake,
            $depensa,
            app(FindingAdjudicator::class),
            app(AninoCandidateSelector::class),
            $ollama,
        );
    }

    expect($run->fresh()->next_step)->toBe(2)
        ->and($run->fresh()->status)->toBe('complete_with_errors')
        ->and($run->fresh()->processed_findings)->toBe(1)
        ->and($run->fresh()->reviewed_findings)->toBe(0)
        ->and($run->fresh()->failed_findings)->toBe(1);
});

test('anino circuit breaks when ollama is unavailable and leaves findings retryable', function () {
    Queue::fake();
    config()->set('services.ollama.models.atake', 'test-atake');
    config()->set('services.ollama.models.depensa', 'test-depensa');

    $scan = Scan::factory()->create();
    $findings = Finding::factory()->count(2)->for($scan)->create();

    foreach ($findings as $finding) {
        FindingAiContext::create([
            'finding_id' => $finding->id,
            'source_commit' => $scan->commit_sha,
            'context_hash' => hash('sha256', 'context-'.$finding->id),
            'metadata' => [],
            'context' => 'scanner evidence',
        ]);
    }

    $run = AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'queued',
        'phase' => 'queued',
        'candidate_finding_ids' => $findings->pluck('id')->all(),
        'total_findings' => 2,
        'heartbeat_at' => now(),
    ]);
    $atake = Mockery::mock(AtakeReviewer::class);
    $depensa = Mockery::mock(DepensaReviewer::class);
    $ollama = Mockery::mock(OllamaClient::class);
    $atake->shouldReceive('review')->once()->andThrow(new OllamaUnavailableException('Ollama is offline.'));
    $depensa->shouldNotReceive('review');
    $ollama->shouldNotReceive('unload');

    (new AnalyzeFindingsWithAninoJob($scan->id, $run->id))->handle(
        $atake,
        $depensa,
        app(FindingAdjudicator::class),
        app(AninoCandidateSelector::class),
        $ollama,
    );

    expect($run->fresh()->status)->toBe('failed')
        ->and($run->fresh()->phase)->toBe('unavailable')
        ->and($run->fresh()->next_step)->toBe(0)
        ->and($run->fresh()->failed_findings)->toBe(2)
        ->and(app(AninoCandidateSelector::class)->failedFromRun($run->fresh())->all())
        ->toEqualCanonicalizing($findings->pluck('id')->all());

    Queue::assertNothingPushed();
});

test('anino waits without inference when another scan owns the ollama runtime', function () {
    Queue::fake();
    config()->set('services.ollama.runtime_lock', 'test-shared-ollama-runtime');

    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->create();
    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'waiting-context'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);
    $run = AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'queued',
        'phase' => 'queued',
        'candidate_finding_ids' => [$finding->id],
        'total_findings' => 1,
        'heartbeat_at' => now(),
    ]);
    $runtimeLock = Cache::lock('test-shared-ollama-runtime', 60);
    expect($runtimeLock->get())->toBeTrue();

    try {
        $atake = Mockery::mock(AtakeReviewer::class);
        $depensa = Mockery::mock(DepensaReviewer::class);
        $ollama = Mockery::mock(OllamaClient::class);
        $atake->shouldNotReceive('review');
        $depensa->shouldNotReceive('review');
        $ollama->shouldNotReceive('unload');

        (new AnalyzeFindingsWithAninoJob($scan->id, $run->id, 0))->handle(
            $atake,
            $depensa,
            app(FindingAdjudicator::class),
            app(AninoCandidateSelector::class),
            $ollama,
        );
    } finally {
        $runtimeLock->release();
    }

    expect($run->fresh()->next_step)->toBe(0)
        ->and($run->fresh()->status)->toBe('queued');
    Queue::assertPushed(
        AnalyzeFindingsWithAninoJob::class,
        fn (AnalyzeFindingsWithAninoJob $job) => $job->runId === $run->id
            && $job->expectedStep === 0,
    );
});

test('anino ignores a continuation whose expected cursor is stale', function () {
    Queue::fake();

    $scan = Scan::factory()->create();
    $run = AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'running',
        'phase' => 'atake',
        'candidate_finding_ids' => [999],
        'next_step' => 1,
        'total_findings' => 1,
        'heartbeat_at' => now(),
    ]);
    $atake = Mockery::mock(AtakeReviewer::class);
    $depensa = Mockery::mock(DepensaReviewer::class);
    $ollama = Mockery::mock(OllamaClient::class);
    $atake->shouldNotReceive('review');
    $depensa->shouldNotReceive('review');
    $ollama->shouldNotReceive('unload');

    (new AnalyzeFindingsWithAninoJob($scan->id, $run->id, 0))->handle(
        $atake,
        $depensa,
        app(FindingAdjudicator::class),
        app(AninoCandidateSelector::class),
        $ollama,
    );

    expect($run->fresh()->next_step)->toBe(1);
    Queue::assertNothingPushed();
});

test('ollama requests use bounded inference settings', function () {
    config()->set('services.ollama.enabled', true);
    config()->set('services.ollama.num_ctx', 4096);
    config()->set('services.ollama.num_predict', 320);
    config()->set('services.ollama.keep_alive', '30m');
    Http::fake([
        '*' => Http::response([
            'message' => ['content' => json_encode(aninoReview('atake', 'test-model')['result'])],
            'prompt_eval_count' => 100,
            'eval_count' => 50,
            'total_duration' => 1_000_000_000,
        ]),
    ]);

    app(OllamaClient::class)->chat('test-model', [
        ['role' => 'user', 'content' => 'evidence'],
    ], AiAssessmentSchema::make());

    Http::assertSent(fn (HttpRequest $request) => $request['keep_alive'] === '30m'
        && $request['options']['num_ctx'] === 4096
        && $request['options']['num_predict'] === 320
        && $request['stream'] === false
    );
});

test('ollama accepts a phase keep alive override and explicitly unloads the model', function () {
    config()->set('services.ollama.enabled', true);
    Http::fake([
        '*/api/chat' => Http::response([
            'message' => ['content' => json_encode(aninoReview('atake', 'test-model')['result'])],
        ]),
        '*/api/generate' => Http::response(['done' => true]),
    ]);

    $client = app(OllamaClient::class);
    $client->chat(
        'test-model',
        [['role' => 'user', 'content' => 'evidence']],
        AiAssessmentSchema::make(),
        '5m',
    );
    $client->unload('test-model');

    Http::assertSentCount(2);
    Http::assertSent(fn (HttpRequest $request) => str_ends_with($request->url(), '/api/chat')
        && $request['keep_alive'] === '5m');
    Http::assertSent(fn (HttpRequest $request) => str_ends_with($request->url(), '/api/generate')
        && $request['model'] === 'test-model'
        && $request['keep_alive'] === 0);
});

test('reviewers keep separate gpu profiles when they share one model tag', function () {
    config()->set('services.ollama.enabled', true);
    config()->set('services.ollama.models.atake', 'shared-model');
    config()->set('services.ollama.models.depensa', 'shared-model');
    config()->set('services.ollama.num_gpu.atake', 11);
    config()->set('services.ollama.num_gpu.depensa', 22);

    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->create();
    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'profile-context'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);
    Http::fake(['*' => Http::response([
        'message' => ['content' => json_encode(aninoReview('atake', 'shared-model')['result'])],
    ])]);

    app(AtakeReviewer::class)->review($finding);
    app(DepensaReviewer::class)->review($finding);

    $requests = Http::recorded();

    expect($requests)->toHaveCount(2)
        ->and($requests[0][0]['options']['num_gpu'])->toBe(11)
        ->and($requests[1][0]['options']['num_gpu'])->toBe(22);
});

test('ollama identifies a terminated local model runtime as unavailable', function () {
    config()->set('services.ollama.enabled', true);
    Http::fake([
        '*' => Http::response([
            'error' => 'llama-server process has terminated: CUDA error: shared object initialization failed',
        ], 500),
    ]);

    expect(fn () => app(OllamaClient::class)->chat(
        'test-model',
        [['role' => 'user', 'content' => 'evidence']],
        AiAssessmentSchema::make(),
    ))->toThrow(OllamaUnavailableException::class, 'runtime terminated');
});

test('ollama treats missing models and transient service responses as unavailable', function (int $status, string $body) {
    config()->set('services.ollama.enabled', true);
    Http::fake(['*' => Http::response($body, $status)]);

    expect(fn () => app(OllamaClient::class)->chat(
        'missing-model',
        [['role' => 'user', 'content' => 'evidence']],
        AiAssessmentSchema::make(),
    ))->toThrow(OllamaUnavailableException::class);
})->with([
    'missing model' => [404, '{"error":"model missing-model not found"}'],
    'service unavailable' => [503, 'service unavailable'],
]);

test('ollama repairs unescaped control characters inside structured strings', function () {
    config()->set('services.ollama.enabled', true);
    $content = json_encode([
        'classification' => 'likely_tp',
        'reasoning_summary' => "First line\nSecond line\twith detail",
    ], JSON_THROW_ON_ERROR);
    $content = str_replace(['\\n', '\\t'], ["\n", "\t"], $content);

    Http::fake([
        '*' => Http::response([
            'message' => ['content' => $content],
        ]),
    ]);

    $response = app(OllamaClient::class)->chat(
        'test-model',
        [['role' => 'user', 'content' => 'evidence']],
        AiAssessmentSchema::make(),
    );

    expect($response['content']['classification'])->toBe('likely_tp')
        ->and($response['content']['reasoning_summary'])->toBe("First line\nSecond line\twith detail");
});

test('ollama still rejects malformed structured json', function () {
    config()->set('services.ollama.enabled', true);
    Http::fake([
        '*' => Http::response([
            'message' => ['content' => '{"classification":'],
        ]),
    ]);

    expect(fn () => app(OllamaClient::class)->chat(
        'test-model',
        [['role' => 'user', 'content' => 'evidence']],
        AiAssessmentSchema::make(),
    ))->toThrow(RuntimeException::class, 'Ollama returned invalid structured JSON');
});

test('scan can promote high confidence anino adjudications into rubix training labels', function () {
    Queue::fake();
    config()->set('sast.ai_training.confidence_threshold', 0.85);

    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->vectorized()->create();

    AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => 'adjudicator',
        'model' => 'deterministic-rules-v1',
        'classification' => 'likely_tp',
        'confidence' => 0.91,
        'preconditions' => [],
        'supporting_evidence' => [],
        'contradicting_evidence' => [],
        'missing_evidence' => [],
        'remediation' => [],
        'reasoning_summary' => 'ATAKE and DEPENSA agree.',
        'prompt_version' => 'rules-v1',
        'completed_at' => now(),
    ]);

    $this->actingAs($user)
        ->post(route('scans.anino.train', $scan))
        ->assertRedirect()
        ->assertSessionHas('success');

    expect($finding->fresh()->final_label)->toBe('true_positive')
        ->and(TriageFeedback::sole()->corrected_label)->toBe('true_positive');

    Queue::assertPushed(TrainSastModelJob::class);
});

test('scan does not promote low confidence anino adjudications', function () {
    Queue::fake();
    config()->set('sast.ai_training.confidence_threshold', 0.85);

    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->vectorized()->create();

    AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => 'adjudicator',
        'model' => 'deterministic-rules-v1',
        'classification' => 'likely_fp',
        'confidence' => 0.60,
        'preconditions' => [],
        'supporting_evidence' => [],
        'contradicting_evidence' => [],
        'missing_evidence' => [],
        'remediation' => [],
        'reasoning_summary' => 'Weak agreement.',
        'prompt_version' => 'rules-v1',
        'completed_at' => now(),
    ]);

    $this->actingAs($user)
        ->post(route('scans.anino.train', $scan))
        ->assertRedirect()
        ->assertSessionHas('error');

    expect($finding->fresh()->final_label)->toBeNull()
        ->and(TriageFeedback::count())->toBe(0);

    Queue::assertNotPushed(TrainSastModelJob::class);
});

/**
 * @return array<string, mixed>
 */
function aninoReview(string $reviewer, string $model): array
{
    return [
        'reviewer' => $reviewer,
        'model' => $model,
        'prompt_version' => $reviewer.'-v2',
        'result' => [
            'classification' => 'likely_tp',
            'confidence' => 0.8,
            'attacker_controlled' => true,
            'sink_reachable' => true,
            'mitigation_detected' => false,
            'preconditions' => [],
            'supporting_evidence' => [],
            'contradicting_evidence' => [],
            'missing_evidence' => [],
            'remediation' => [],
            'reasoning_summary' => 'The finding is supported.',
        ],
        'usage' => [],
        'raw' => [],
    ];
}
