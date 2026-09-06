<?php

use App\Exceptions\InsufficientTrainingDataException;
use App\Jobs\TrainSastModelJob;
use App\Models\Finding;
use App\Models\ModelState;
use App\Models\User;
use App\Services\RubixTriageService;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Str;

/**
 * Covers the end-to-end training loop: readiness accounting, the guards that
 * stop a useless training run, a real Rubix fit over labeled findings, and
 * the inference path that fit unlocks.
 */
beforeEach(function () {
    $this->user = User::factory()->create();

    // Keep the fixtures small — the guards, not the sample count, are what
    // these tests are about. Each test gets its own model file so runs can't
    // leak a trained model into a cold-start assertion.
    config()->set('sast.training.min_training_samples', 20);
    config()->set('sast.training.model_path', 'testing/'.Str::uuid().'.rbx');

    $this->modelPath = app(RubixTriageService::class)->modelPath();
});

afterEach(function () {
    if (isset($this->modelPath) && file_exists($this->modelPath)) {
        unlink($this->modelPath);
    }
});

it('reports how far the label set is from being trainable', function () {
    Finding::factory()->count(6)->labeled('true_positive')->create();
    Finding::factory()->count(4)->labeled('false_positive')->create();

    $readiness = app(RubixTriageService::class)->trainingReadiness();

    expect($readiness)->toMatchArray([
        'total' => 10,
        'true_positive' => 6,
        'false_positive' => 4,
        'required' => 20,
        'ready' => false,
    ]);
});

it('does not count unlabeled or unvectorized findings as training data', function () {
    Finding::factory()->count(5)->vectorized()->create();                     // no final_label
    Finding::factory()->count(5)->create(['final_label' => 'true_positive']); // no feature_vector

    expect(app(RubixTriageService::class)->trainingReadiness()['total'])->toBe(0);
});

it('refuses to train below the minimum label count', function () {
    Finding::factory()->count(5)->labeled('true_positive')->create();
    Finding::factory()->count(5)->labeled('false_positive')->create();

    app(RubixTriageService::class)->train();
})->throws(InsufficientTrainingDataException::class, 'Insufficient labeled data');

it('refuses to train on a single-class label set', function () {
    // A model fit on one class answers the same label at full confidence for
    // every finding — worse than having no model at all.
    Finding::factory()->count(25)->labeled('true_positive')->create();

    app(RubixTriageService::class)->train();
})->throws(InsufficientTrainingDataException::class, 'both classes');

it('trains a real model from labeled findings and persists it', function () {
    $service = app(RubixTriageService::class);

    expect($service->hasTrainedModel())->toBeFalse();

    seedSeparableLabels();

    $metrics = $service->train();

    expect($service->hasTrainedModel())->toBeTrue()
        ->and(file_exists($this->modelPath))->toBeTrue()
        ->and($metrics['precision'])->toBeGreaterThanOrEqual(0.0)->toBeLessThanOrEqual(1.0)
        ->and($metrics['recall'])->toBeGreaterThanOrEqual(0.0)->toBeLessThanOrEqual(1.0)
        ->and($metrics['f1_score'])->toBeGreaterThanOrEqual(0.0)->toBeLessThanOrEqual(1.0)
        ->and($metrics['confusion'])->toHaveKeys(['tp', 'fp', 'fn', 'tn'])
        ->and($metrics['trained_on'])->toBeGreaterThan(0);
});

it('learns a signal that separates the two classes', function () {
    seedSeparableLabels();

    $metrics = app(RubixTriageService::class)->train();

    // The fixture makes the classes cleanly separable, so a correctly wired
    // pipeline scores well above chance. This is the assertion that proves
    // the Rubix integration works rather than merely not throwing.
    expect($metrics['f1_score'])->toBeGreaterThan(0.7);
});

it('scores new findings once a model exists', function () {
    seedSeparableLabels();
    app(RubixTriageService::class)->train();

    $unscored = Finding::factory()->count(3)->vectorized()->create();

    expect($unscored->every(fn (Finding $f) => $f->predicted_label === null))->toBeTrue();

    expect(app(RubixTriageService::class)->predictBatch($unscored))->toBe(3);

    $unscored->each(function (Finding $finding) {
        $finding->refresh();

        expect($finding->predicted_label)->toBeIn(['true_positive', 'false_positive'])
            ->and($finding->tp_probability)->toBeGreaterThanOrEqual(0.0)->toBeLessThanOrEqual(1.0);
    });
});

it('scores nothing and throws nothing before the first training run', function () {
    $findings = Finding::factory()->count(3)->vectorized()->create();

    expect(app(RubixTriageService::class)->predictBatch($findings))->toBe(0)
        ->and($findings->first()->fresh()->predicted_label)->toBeNull();
});

it('records a ModelState row when the training job runs', function () {
    seedSeparableLabels();

    (new TrainSastModelJob)->handle(app(RubixTriageService::class));

    expect(ModelState::count())->toBe(1);

    $state = ModelState::first();

    expect($state->sample_size)->toBeGreaterThan(0)
        ->and($state->confusion_matrix)->toHaveKeys(['tp', 'fp', 'fn', 'tn']);
});

it('treats insufficient data as a skip, not a job failure', function () {
    Finding::factory()->count(3)->labeled('true_positive')->create();

    (new TrainSastModelJob)->handle(app(RubixTriageService::class));

    expect(ModelState::count())->toBe(0)
        ->and(cache()->has('sast:retrain-lock'))->toBeFalse();
});

it('exposes training status to the dashboard', function () {
    Finding::factory()->count(3)->labeled('true_positive')->create();
    ModelState::factory()->create(['f1_score' => 0.87]);

    $this->actingAs($this->user)
        ->get(route('model.index'))
        ->assertOk()
        ->assertInertia(fn ($page) => $page
            ->component('Model/Index')
            ->where('readiness.total', 3)
            ->where('readiness.ready', false)
            ->where('latest.f1_score', 0.87)
        );
});

it('queues a training run from the dashboard when there is enough data', function () {
    Queue::fake();
    seedSeparableLabels();

    $this->actingAs($this->user)
        ->post(route('model.train'))
        ->assertRedirect()
        ->assertSessionHas('success');

    Queue::assertPushedOn('ml-training', TrainSastModelJob::class);
});

it('blocks a dashboard training run that would fail', function () {
    Queue::fake();
    Finding::factory()->count(3)->labeled('true_positive')->create();

    $this->actingAs($this->user)
        ->post(route('model.train'))
        ->assertRedirect()
        ->assertSessionHas('error');

    Queue::assertNothingPushed();
});

it('rejects a second concurrent training run', function () {
    Queue::fake();
    seedSeparableLabels();

    $this->actingAs($this->user)->postJson(route('api.model.train'))->assertStatus(202);
    $this->actingAs($this->user)->postJson(route('api.model.train'))->assertStatus(409);

    Queue::assertPushed(TrainSastModelJob::class, 1);
});

it('returns the specific shortfall from the training endpoint', function () {
    Finding::factory()->count(3)->labeled('true_positive')->create();

    $this->actingAs($this->user)
        ->postJson(route('api.model.train'))
        ->assertStatus(422)
        ->assertJsonPath('readiness.total', 3)
        ->assertJsonPath('readiness.required', 20);
});

it('requires authentication to trigger training', function () {
    $this->postJson(route('api.model.train'))->assertUnauthorized();
});

/**
 * Builds a label set the classifier can actually learn from: low-complexity
 * sanitized findings in test files are false positives, complex unsanitized
 * ones are true positives.
 */
function seedSeparableLabels(int $perClass = 15): void
{
    foreach (range(1, $perClass) as $i) {
        Finding::factory()->create([
            'final_label' => 'true_positive',
            'status' => 'triaged',
            'feature_vector' => [
                'cwe_id' => 89,
                'scanner_severity' => 'HIGH',
                'file_extension' => 'php',
                'is_test_file' => 0,
                'cyclomatic_complexity' => 12 + ($i % 5),
                'has_sanitizer_in_ast' => 0,
                'line_depth_in_function' => 15 + ($i % 7),
                'historical_fp_rate_rule' => 0.05,
                'developer_experience_lvl' => 'junior',
            ],
        ]);

        Finding::factory()->create([
            'final_label' => 'false_positive',
            'status' => 'triaged',
            'feature_vector' => [
                'cwe_id' => 79,
                'scanner_severity' => 'LOW',
                'file_extension' => 'php',
                'is_test_file' => 1,
                'cyclomatic_complexity' => 2 + ($i % 3),
                'has_sanitizer_in_ast' => 1,
                'line_depth_in_function' => 2 + ($i % 4),
                'historical_fp_rate_rule' => 0.92,
                'developer_experience_lvl' => 'senior',
            ],
        ]);
    }
}
