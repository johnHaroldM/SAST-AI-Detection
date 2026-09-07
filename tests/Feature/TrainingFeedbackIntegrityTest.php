<?php

use App\Models\AiAssessment;
use App\Models\Finding;
use App\Models\FindingAiContext;
use App\Models\Scan;
use App\Models\TriageFeedback;
use App\Models\User;
use App\Services\AI\AiTrainingPromoter;
use App\Services\AI\FindingAdjudicator;

test('repeated triage corrects one canonical feedback row', function () {
    $firstUser = User::factory()->create();
    $secondUser = User::factory()->create();
    $finding = Finding::factory()->scored('true_positive', 0.91)->create();

    $this->actingAs($firstUser)->postJson(route('api.findings.triage', $finding), [
        'corrected_label' => 'false_positive',
        'notes' => 'Initial decision.',
    ])->assertOk();

    $this->actingAs($secondUser)->postJson(route('api.findings.triage', $finding), [
        'corrected_label' => 'true_positive',
        'notes' => 'Corrected after reviewing the full data flow.',
    ])->assertOk();

    $feedback = TriageFeedback::sole();

    expect($finding->fresh()->final_label)->toBe('true_positive')
        ->and($feedback->corrected_label)->toBe('true_positive')
        ->and($feedback->user_id)->toBe($secondUser->id)
        ->and($feedback->source)->toBe('human')
        ->and($feedback->notes)->toBe('Corrected after reviewing the full data flow.');
});

test('bulk triage deduplicates repeated finding ids and reports actual updates', function () {
    $user = User::factory()->create();
    $finding = Finding::factory()->vectorized()->create();

    $this->actingAs($user)
        ->postJson(route('api.findings.bulk-triage'), [
            'decisions' => [
                ['finding_id' => $finding->id, 'corrected_label' => 'false_positive'],
                ['finding_id' => $finding->id, 'corrected_label' => 'true_positive'],
            ],
        ])
        ->assertOk()
        ->assertJsonPath('updated', 1);

    expect(TriageFeedback::count())->toBe(1)
        ->and(TriageFeedback::sole()->corrected_label)->toBe('true_positive')
        ->and($finding->fresh()->final_label)->toBe('true_positive');
});

test('false positive agreement uses class aligned confidence and records weak label provenance', function () {
    config()->set('sast.ai_training.confidence_threshold', 0.85);

    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->vectorized()->scored('false_positive', 0.10)->create();

    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => hash('sha256', 'false-positive-context'),
        'metadata' => [],
        'context' => 'scanner evidence',
    ]);

    foreach (['atake', 'depensa'] as $reviewer) {
        config()->set("services.ollama.models.{$reviewer}", 'test-'.$reviewer);

        AiAssessment::create([
            'finding_id' => $finding->id,
            'reviewer' => $reviewer,
            'model' => 'test-'.$reviewer,
            'classification' => 'confirmed_fp',
            'confidence' => 1.0,
            'missing_evidence' => [],
            'prompt_version' => $reviewer.'-v2',
            'context_hash' => $finding->aiContext->context_hash,
            'completed_at' => now(),
        ]);
    }

    app(FindingAdjudicator::class)->update($finding);

    $adjudication = $finding->aiAssessments()->where('reviewer', 'adjudicator')->sole();

    expect($adjudication->classification)->toBe('likely_fp')
        ->and($adjudication->confidence)->toBeGreaterThanOrEqual(0.85);

    $result = app(AiTrainingPromoter::class)->promote($scan, $user->id);
    $feedback = TriageFeedback::sole();

    expect($result['false_positive'])->toBe(1)
        ->and($finding->fresh()->final_label)->toBe('false_positive')
        ->and($feedback->source)->toBe('ai_pseudo')
        ->and($feedback->source_ai_assessment_id)->toBe($adjudication->id);
});
