<?php

use App\Jobs\AnalyzeFindingsWithAninoJob;
use App\Jobs\TrainSastModelJob;
use App\Models\AiAssessment;
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
        'prompt_version' => 'atake-v1',
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

test('anino processes one finding per queued job', function () {
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
    $atake->shouldReceive('review')->once()->andReturn(aninoReview('atake', 'test-atake'));
    $depensa->shouldReceive('review')->once()->andReturn(aninoReview('depensa', 'test-depensa'));

    (new AnalyzeFindingsWithAninoJob($scan->id, $run->id))->handle(
        $atake,
        $depensa,
        app(FindingAdjudicator::class),
        app(AninoCandidateSelector::class),
    );

    $run->refresh();

    expect($run->processed_findings)->toBe(1)
        ->and($run->reviewed_findings)->toBe(1)
        ->and($run->status)->toBe('running')
        ->and(AiAssessment::where('finding_id', $findings[0]->id)->count())->toBe(3)
        ->and(AiAssessment::where('finding_id', $findings[1]->id)->count())->toBe(0);

    Queue::assertPushed(AnalyzeFindingsWithAninoJob::class, fn ($job) => $job->runId === $run->id);
});

test('anino resumes a partially reviewed finding without repeating the model call', function () {
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
        'prompt_version' => 'atake-v1',
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
    $atake->shouldNotReceive('review');
    $depensa->shouldReceive('review')->once()->andReturn(aninoReview('depensa', 'test-depensa'));

    (new AnalyzeFindingsWithAninoJob($scan->id, $run->id))->handle(
        $atake,
        $depensa,
        app(FindingAdjudicator::class),
        app(AninoCandidateSelector::class),
    );

    expect($run->fresh()->status)->toBe('complete')
        ->and($run->fresh()->processed_findings)->toBe(1)
        ->and(AiAssessment::where('finding_id', $finding->id)->where('reviewer', 'atake')->count())->toBe(1)
        ->and(AiAssessment::where('finding_id', $finding->id)->where('reviewer', 'adjudicator')->exists())->toBeTrue();
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
