<?php

use App\Jobs\TrainSastModelJob;
use App\Models\AiAssessment;
use App\Models\AiAssessmentFeedback;
use App\Models\Finding;
use App\Models\User;
use Illuminate\Support\Facades\Queue;

function assessmentForFeedback(string $reviewer = 'atake'): AiAssessment
{
    return AiAssessment::create([
        'finding_id' => Finding::factory()->create()->id,
        'reviewer' => $reviewer,
        'model' => 'feedback-test-model',
        'classification' => 'likely_tp',
        'confidence' => 0.8,
        'prompt_version' => $reviewer.'-v1',
        'completed_at' => now(),
    ]);
}

test('an authenticated reviewer can submit feedback for an ai assessment', function () {
    Queue::fake();

    $user = User::factory()->create();
    $assessment = assessmentForFeedback('atake');
    $finding = $assessment->finding;

    $this->actingAs($user)
        ->putJson(route('api.ai-assessments.feedback.update', $assessment), [
            'verdict' => 'incorrect',
            'corrected_classification' => 'confirmed_fp',
            'reason_codes' => ['missed_sanitizer', 'incorrect_data_flow'],
            'notes' => 'A framework sanitizer makes the reported path unreachable.',
        ])
        ->assertCreated()
        ->assertJsonPath('feedback.assessment_id', $assessment->id)
        ->assertJsonPath('feedback.user_id', $user->id)
        ->assertJsonPath('feedback.verdict', 'incorrect')
        ->assertJsonPath('feedback.corrected_classification', 'confirmed_fp')
        ->assertJsonPath('feedback.reason_codes.0', 'missed_sanitizer');

    $feedback = AiAssessmentFeedback::sole();

    expect($feedback->reason_codes)->toBe(['missed_sanitizer', 'incorrect_data_flow'])
        ->and($feedback->reviewed_at)->not->toBeNull()
        ->and($assessment->fresh()->feedback->sole()->is($feedback))->toBeTrue()
        ->and($finding->fresh()->final_label)->toBeNull()
        ->and($finding->fresh()->status)->toBe('pending');

    Queue::assertNotPushed(TrainSastModelJob::class);
});

test('put upserts one feedback row per assessment and user', function () {
    $user = User::factory()->create();
    $assessment = assessmentForFeedback('depensa');

    $this->actingAs($user)
        ->putJson(route('api.ai-assessments.feedback.update', $assessment), [
            'verdict' => 'partially_correct',
            'corrected_classification' => 'needs_validation',
            'reason_codes' => ['weak_reasoning'],
        ])
        ->assertCreated();

    $feedbackId = AiAssessmentFeedback::sole()->id;

    $this->travel(1)->minute();

    $this->actingAs($user)
        ->putJson(route('api.ai-assessments.feedback.update', $assessment), [
            'verdict' => 'correct',
        ])
        ->assertOk()
        ->assertJsonPath('feedback.id', $feedbackId)
        ->assertJsonPath('feedback.verdict', 'correct')
        ->assertJsonPath('feedback.corrected_classification', null)
        ->assertJsonPath('feedback.reason_codes', null);

    expect(AiAssessmentFeedback::count())->toBe(1)
        ->and(AiAssessmentFeedback::sole()->corrected_classification)->toBeNull()
        ->and(AiAssessmentFeedback::sole()->reason_codes)->toBeNull();
});

test('feedback validation requires a correction for disagreement verdicts', function (string $verdict) {
    $user = User::factory()->create();
    $assessment = assessmentForFeedback();

    $this->actingAs($user)
        ->putJson(route('api.ai-assessments.feedback.update', $assessment), [
            'verdict' => $verdict,
        ])
        ->assertUnprocessable()
        ->assertJsonValidationErrors('corrected_classification');

    expect(AiAssessmentFeedback::count())->toBe(0);
})->with(['incorrect', 'partially_correct']);

test('feedback rejects unsupported verdicts classifications and reason codes', function () {
    $user = User::factory()->create();
    $assessment = assessmentForFeedback();

    $this->actingAs($user)
        ->putJson(route('api.ai-assessments.feedback.update', $assessment), [
            'verdict' => 'mostly_correct',
            'corrected_classification' => 'definitely_safe',
            'reason_codes' => ['arbitrary_reason'],
        ])
        ->assertUnprocessable()
        ->assertJsonValidationErrors([
            'verdict',
            'corrected_classification',
            'reason_codes.0',
        ]);
});

test('feedback is limited to atake and depensa assessments', function () {
    $user = User::factory()->create();
    $assessment = assessmentForFeedback('adjudicator');

    $this->actingAs($user)
        ->putJson(route('api.ai-assessments.feedback.update', $assessment), [
            'verdict' => 'correct',
        ])
        ->assertUnprocessable()
        ->assertJsonValidationErrors('ai_assessment');
});

test('retraction removes only the authenticated users feedback', function () {
    [$firstUser, $secondUser] = User::factory()->count(2)->create();
    $assessment = assessmentForFeedback();

    foreach ([$firstUser, $secondUser] as $user) {
        $this->actingAs($user)
            ->putJson(route('api.ai-assessments.feedback.update', $assessment), [
                'verdict' => 'correct',
            ])
            ->assertCreated();
    }

    $this->actingAs($firstUser)
        ->deleteJson(route('api.ai-assessments.feedback.destroy', $assessment))
        ->assertNoContent();

    expect(AiAssessmentFeedback::count())->toBe(1)
        ->and(AiAssessmentFeedback::sole()->user_id)->toBe($secondUser->id);
});

test('feedback endpoints require authentication', function () {
    $assessment = assessmentForFeedback();

    $this->putJson(route('api.ai-assessments.feedback.update', $assessment), [
        'verdict' => 'correct',
    ])->assertUnauthorized();

    $this->deleteJson(route('api.ai-assessments.feedback.destroy', $assessment))
        ->assertUnauthorized();
});

test('feedback is deleted with its assessment or reviewer', function () {
    $firstUser = User::factory()->create();
    $firstAssessment = assessmentForFeedback();

    AiAssessmentFeedback::create([
        'assessment_id' => $firstAssessment->id,
        'user_id' => $firstUser->id,
        'verdict' => 'correct',
        'reviewed_at' => now(),
    ]);

    $firstAssessment->delete();

    expect(AiAssessmentFeedback::count())->toBe(0);

    $secondUser = User::factory()->create();
    $secondAssessment = assessmentForFeedback('depensa');

    AiAssessmentFeedback::create([
        'assessment_id' => $secondAssessment->id,
        'user_id' => $secondUser->id,
        'verdict' => 'correct',
        'reviewed_at' => now(),
    ]);

    $secondUser->delete();

    expect(AiAssessmentFeedback::count())->toBe(0);
});
