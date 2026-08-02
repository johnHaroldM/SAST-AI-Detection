<?php

use App\Jobs\TrainSastModelJob;
use App\Models\Finding;
use App\Models\ModelState;
use App\Models\Rule;
use App\Models\TriageFeedback;
use App\Models\User;
use App\Services\RubixTriageService;
use Illuminate\Support\Facades\Queue;

/**
 * The human-in-the-loop half of the training story: triage decisions have to
 * become labeled training rows, and they have to feed the rule noise rate
 * back into future feature vectors.
 */
beforeEach(function () {
    $this->user = User::factory()->create();
    config()->set('sast.training.min_training_samples', 20);
});

it('turns a triage decision into labeled training data', function () {
    $finding = Finding::factory()->scored('true_positive', 0.91)->create();

    $this->actingAs($this->user)
        ->postJson(route('api.findings.triage', $finding), [
            'corrected_label' => 'false_positive',
            'notes' => 'Input is bound via a prepared statement two frames up.',
        ])
        ->assertOk()
        ->assertJsonPath('final_label', 'false_positive')
        ->assertJsonPath('status', 'triaged');

    $finding->refresh();

    expect($finding->final_label)->toBe('false_positive')
        ->and($finding->status)->toBe('triaged');

    $feedback = TriageFeedback::sole();

    expect($feedback->original_prediction)->toBe('true_positive')
        ->and((float) $feedback->original_probability)->toBe(0.91)
        ->and($feedback->corrected_label)->toBe('false_positive')
        ->and($feedback->user_id)->toBe($this->user->id);

    // The decision must now be visible to the trainer.
    expect(app(RubixTriageService::class)->trainingReadiness()['false_positive'])->toBe(1);
});

it('recalculates the rule false-positive rate after triage', function () {
    $rule = Rule::factory()->create(['external_id' => 'php.security.sqli']);

    $findings = Finding::factory()->count(4)->vectorized()->create(['rule_id' => 'php.security.sqli']);

    foreach ($findings->take(3) as $finding) {
        $this->actingAs($this->user)->postJson(route('api.findings.triage', $finding), [
            'corrected_label' => 'false_positive',
        ])->assertOk();
    }

    $this->actingAs($this->user)->postJson(route('api.findings.triage', $findings->last()), [
        'corrected_label' => 'true_positive',
    ])->assertOk();

    $rule->refresh();

    expect($rule->total_seen)->toBe(4)
        ->and($rule->total_false_positive)->toBe(3)
        ->and($rule->historical_fp_rate)->toBe(0.75);
});

it('recommends suppressing a rule once its FP rate clears the high threshold', function () {
    config()->set('sast.rules.min_samples', 4);

    $rule = Rule::factory()->create(['external_id' => 'php.noisy.rule']);
    Finding::factory()->count(5)->vectorized()->create([
        'rule_id' => 'php.noisy.rule',
        'final_label' => 'false_positive',
    ]);

    $rule->recalculateFpRate();

    // 100% FP over 5 samples clears the 85% suppress threshold. The previous
    // ordering checked 70% first, so 'suppress' was unreachable.
    expect($rule->historical_fp_rate)->toBe(1.0)
        ->and($rule->recommended_action)->toBe('suppress');
});

it('recommends reviewing config in the middle band', function () {
    config()->set('sast.rules.min_samples', 4);

    $rule = Rule::factory()->create(['external_id' => 'php.middling.rule']);
    Finding::factory()->count(3)->vectorized()->create([
        'rule_id' => 'php.middling.rule',
        'final_label' => 'false_positive',
    ]);
    Finding::factory()->count(1)->vectorized()->create([
        'rule_id' => 'php.middling.rule',
        'final_label' => 'true_positive',
    ]);

    $rule->recalculateFpRate();

    expect($rule->historical_fp_rate)->toBe(0.75)
        ->and($rule->recommended_action)->toBe('review_config');
});

it('leaves a rule unflagged below the sample floor', function () {
    config()->set('sast.rules.min_samples', 20);

    $rule = Rule::factory()->create(['external_id' => 'php.rare.rule']);
    Finding::factory()->count(3)->vectorized()->create([
        'rule_id' => 'php.rare.rule',
        'final_label' => 'false_positive',
    ]);

    $rule->recalculateFpRate();

    expect($rule->historical_fp_rate)->toBe(1.0)
        ->and($rule->recommended_action)->toBeNull();
});

it('records a label for every finding in a bulk triage', function () {
    $findings = Finding::factory()->count(5)->vectorized()->create();

    $this->actingAs($this->user)
        ->postJson(route('api.findings.bulk-triage'), [
            'decisions' => $findings->map(fn (Finding $f) => [
                'finding_id' => $f->id,
                'corrected_label' => 'true_positive',
            ])->all(),
        ])
        ->assertOk()
        ->assertJsonPath('updated', 5);

    expect(Finding::whereNotNull('final_label')->count())->toBe(5)
        ->and(TriageFeedback::count())->toBe(5)
        ->and(app(RubixTriageService::class)->trainingReadiness()['true_positive'])->toBe(5);
});

it('auto-queues retraining once the label batch threshold is crossed', function () {
    Queue::fake();
    config()->set('sast.training.retrain_batch_size', 5);

    $findings = Finding::factory()->count(5)->vectorized()->create();

    $this->actingAs($this->user)
        ->postJson(route('api.findings.bulk-triage'), [
            'decisions' => $findings->map(fn (Finding $f) => [
                'finding_id' => $f->id,
                'corrected_label' => 'true_positive',
            ])->all(),
        ])
        ->assertOk();

    Queue::assertPushedOn('ml-training', TrainSastModelJob::class);
});

it('counts only labels added since the last training run', function () {
    Queue::fake();
    config()->set('sast.training.retrain_batch_size', 5);

    // Six labels already folded into a completed training run.
    Finding::factory()->count(6)->labeled('true_positive')->create();
    ModelState::factory()->create(['trained_at' => now()->addSecond()]);

    // A single new decision must not re-trigger training just because the
    // historical total is over the threshold.
    $finding = Finding::factory()->vectorized()->create();

    $this->actingAs($this->user)
        ->postJson(route('api.findings.triage', $finding), ['corrected_label' => 'true_positive'])
        ->assertOk();

    Queue::assertNotPushed(TrainSastModelJob::class);
});

it('rejects an unknown label', function () {
    $finding = Finding::factory()->vectorized()->create();

    $this->actingAs($this->user)
        ->postJson(route('api.findings.triage', $finding), ['corrected_label' => 'maybe'])
        ->assertStatus(422)
        ->assertJsonValidationErrors('corrected_label');
});

it('requires authentication to submit triage decisions', function () {
    $finding = Finding::factory()->vectorized()->create();

    $this->postJson(route('api.findings.triage', $finding), [
        'corrected_label' => 'true_positive',
    ])->assertUnauthorized();

    expect($finding->fresh()->final_label)->toBeNull();
});
