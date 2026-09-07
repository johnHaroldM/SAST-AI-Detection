<?php

use App\Models\AiAssessment;
use App\Models\AiAssessmentFeedback;
use App\Models\AninoAnalysisRun;
use App\Models\Finding;
use App\Models\Scan;
use App\Models\TriageFeedback;
use App\Models\User;
use App\Services\AI\AiEvaluationOutcome;
use Inertia\Testing\AssertableInertia as Assert;

function assessmentForHumanEvaluation(
    Finding $finding,
    string $reviewer,
    string $classification,
    mixed $completedAt = null,
): AiAssessment {
    return AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => $reviewer,
        'model' => 'human-evaluation-test-model',
        'classification' => $classification,
        'confidence' => 0.8,
        'prompt_version' => $reviewer.'-v1',
        'completed_at' => $completedAt ?? now(),
    ]);
}

test('ai reviews use reviewer-as-prediction confusion semantics against human labels', function (
    ?string $finalLabel,
    ?string $classification,
    string $expected,
) {
    expect(AiEvaluationOutcome::classifyAgainstHuman($finalLabel, $classification))->toBe($expected);
})->with([
    'human TP and reviewer TP' => ['true_positive', 'confirmed_tp', 'true_positive'],
    'human FP and reviewer TP' => ['false_positive', 'likely_tp', 'false_positive'],
    'human FP and reviewer FP' => ['false_positive', 'confirmed_fp', 'true_negative'],
    'human TP and reviewer FP' => ['true_positive', 'likely_fp', 'false_negative'],
    'reviewer needs validation' => ['true_positive', 'needs_validation', 'unresolved'],
    'awaiting human label' => [null, 'confirmed_tp', 'unresolved'],
]);

test('anino status reports human-grounded outcomes and awaiting review separately', function () {
    $user = User::factory()->create();
    $scan = Scan::factory()->create();

    $humanTp = Finding::factory()->for($scan)->create(['final_label' => 'true_positive']);
    $humanFp = Finding::factory()->for($scan)->create(['final_label' => 'false_positive']);
    $unresolved = Finding::factory()->for($scan)->create(['final_label' => 'true_positive']);
    $awaiting = Finding::factory()->for($scan)->create(['final_label' => null]);

    assessmentForHumanEvaluation($humanTp, 'atake', 'confirmed_fp', now()->subMinute());
    assessmentForHumanEvaluation($humanTp, 'atake', 'likely_tp', now());
    assessmentForHumanEvaluation($humanTp, 'depensa', 'likely_fp');
    assessmentForHumanEvaluation($humanFp, 'atake', 'confirmed_tp');
    assessmentForHumanEvaluation($humanFp, 'depensa', 'confirmed_fp');
    assessmentForHumanEvaluation($unresolved, 'atake', 'needs_validation');
    assessmentForHumanEvaluation($awaiting, 'atake', 'confirmed_tp');
    assessmentForHumanEvaluation($awaiting, 'depensa', 'confirmed_fp');

    $this->actingAs($user)
        ->getJson(route('api.scans.anino-status', $scan))
        ->assertOk()
        ->assertJsonPath('human_outcomes.atake.true_positive', 1)
        ->assertJsonPath('human_outcomes.atake.false_positive', 1)
        ->assertJsonPath('human_outcomes.atake.true_negative', 0)
        ->assertJsonPath('human_outcomes.atake.false_negative', 0)
        ->assertJsonPath('human_outcomes.atake.unresolved', 1)
        ->assertJsonPath('human_outcomes.atake.awaiting_review', 1)
        ->assertJsonPath('human_outcomes.depensa.true_positive', 0)
        ->assertJsonPath('human_outcomes.depensa.false_positive', 0)
        ->assertJsonPath('human_outcomes.depensa.true_negative', 1)
        ->assertJsonPath('human_outcomes.depensa.false_negative', 1)
        ->assertJsonPath('human_outcomes.depensa.unresolved', 0)
        ->assertJsonPath('human_outcomes.depensa.awaiting_review', 1);
});

test('scan page exposes human outcomes and only the current users assessment feedback', function () {
    [$currentUser, $otherUser] = User::factory()->count(2)->create();
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->create([
        'predicted_label' => 'false_positive',
        'final_label' => 'true_positive',
        'status' => 'triaged',
    ]);
    $assessment = assessmentForHumanEvaluation($finding, 'atake', 'confirmed_fp');

    $currentFeedback = AiAssessmentFeedback::create([
        'assessment_id' => $assessment->id,
        'user_id' => $currentUser->id,
        'verdict' => 'incorrect',
        'corrected_classification' => 'confirmed_tp',
        'reason_codes' => ['incorrect_data_flow'],
        'reviewed_at' => now(),
    ]);
    AiAssessmentFeedback::create([
        'assessment_id' => $assessment->id,
        'user_id' => $otherUser->id,
        'verdict' => 'correct',
        'reviewed_at' => now(),
    ]);

    $this->actingAs($currentUser)
        ->get(route('scans.show', $scan))
        ->assertOk()
        ->assertInertia(fn (Assert $page) => $page
            ->component('Scans/Show')
            ->where('findings.data.0.final_label', 'true_positive')
            ->where('findings.data.0.trusted_final_label', 'true_positive')
            ->where('findings.data.0.ai_assessments.0.human_evaluation_outcome', 'false_negative')
            ->has('findings.data.0.ai_assessments.0.feedback', 1)
            ->where('findings.data.0.ai_assessments.0.feedback.0.id', $currentFeedback->id)
            ->where('findings.data.0.ai_assessments.0.feedback.0.user_id', $currentUser->id)
        );
});

test('ai pseudo labels are excluded from trusted outcomes while labels without feedback remain trusted', function () {
    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $pseudoLabel = Finding::factory()->for($scan)->create([
        'predicted_label' => 'true_positive',
        'tp_probability' => 0.9,
        'final_label' => 'true_positive',
        'status' => 'triaged',
    ]);
    $importedLabel = Finding::factory()->for($scan)->create([
        'predicted_label' => 'false_positive',
        'tp_probability' => 0.1,
        'final_label' => 'false_positive',
        'status' => 'triaged',
    ]);
    $pseudoAssessment = assessmentForHumanEvaluation($pseudoLabel, 'atake', 'confirmed_tp');
    assessmentForHumanEvaluation($importedLabel, 'atake', 'confirmed_fp');

    TriageFeedback::create([
        'finding_id' => $pseudoLabel->id,
        'user_id' => $user->id,
        'corrected_label' => 'true_positive',
        'source' => 'ai_pseudo',
        'source_ai_assessment_id' => $pseudoAssessment->id,
    ]);

    $this->actingAs($user)
        ->getJson(route('api.scans.anino-status', $scan))
        ->assertOk()
        ->assertJsonPath('human_outcomes.atake.true_positive', 0)
        ->assertJsonPath('human_outcomes.atake.true_negative', 1)
        ->assertJsonPath('human_outcomes.atake.awaiting_review', 1);

    $this->actingAs($user)
        ->get(route('scans.show', $scan))
        ->assertOk()
        ->assertInertia(fn (Assert $page) => $page
            ->where('findings.data.0.final_label', 'true_positive')
            ->where('findings.data.0.trusted_final_label', null)
            ->where('findings.data.0.ai_assessments.0.human_evaluation_outcome', 'unresolved')
            ->where('findings.data.1.final_label', 'false_positive')
            ->where('findings.data.1.trusted_final_label', 'false_positive')
            ->where('findings.data.1.ai_assessments.0.human_evaluation_outcome', 'true_negative')
        );
});

test('anino progress counts attempted cursor steps with legacy progress as a fallback', function () {
    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $findings = Finding::factory()->for($scan)->count(2)->create();

    $run = AninoAnalysisRun::create([
        'scan_id' => $scan->id,
        'status' => 'running_with_errors',
        'phase' => 'depensa',
        'candidate_finding_ids' => $findings->pluck('id')->all(),
        'next_step' => 2,
        'total_findings' => 2,
        'heartbeat_at' => now(),
    ]);

    $this->actingAs($user)
        ->getJson(route('api.scans.anino-status', $scan))
        ->assertOk()
        ->assertJsonPath('run.next_step', 2)
        ->assertJsonPath('run.completed_steps', 2)
        ->assertJsonPath('run.progress_percent', 50);

    assessmentForHumanEvaluation($findings->first(), 'atake', 'likely_tp')->update([
        'model' => (string) config('services.ollama.models.atake'),
    ]);
    $run->update(['next_step' => 0]);

    $this->actingAs($user)
        ->getJson(route('api.scans.anino-status', $scan))
        ->assertOk()
        ->assertJsonPath('run.next_step', 0)
        ->assertJsonPath('run.completed_steps', 1)
        ->assertJsonPath('run.progress_percent', 25);
});

test('assessment feedback does not change human ground truth', function () {
    $user = User::factory()->create();
    $scan = Scan::factory()->create();
    $finding = Finding::factory()->for($scan)->create([
        'final_label' => 'true_positive',
        'status' => 'triaged',
    ]);
    $assessment = assessmentForHumanEvaluation($finding, 'depensa', 'likely_tp');

    $this->actingAs($user)
        ->putJson(route('api.ai-assessments.feedback.update', $assessment), [
            'verdict' => 'incorrect',
            'corrected_classification' => 'confirmed_fp',
            'reason_codes' => ['incorrect_data_flow'],
        ])
        ->assertCreated();

    expect($finding->fresh()->final_label)->toBe('true_positive')
        ->and($finding->status)->toBe('triaged');
});
