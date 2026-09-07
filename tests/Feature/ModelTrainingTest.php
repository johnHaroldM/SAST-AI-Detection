<?php

use App\Exceptions\InsufficientTrainingDataException;
use App\Jobs\TrainSastModelJob;
use App\Models\Finding;
use App\Models\ModelState;
use App\Models\Project;
use App\Models\Scan;
use App\Models\TriageFeedback;
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
    config()->set('sast.training.validation_percent', 20);
    config()->set('sast.training.min_validation_true_positives', 3);
    config()->set('sast.training.min_validation_tp_groups', 1);
    config()->set('sast.training.min_deploy_flags', 3);
    config()->set('sast.training.min_deploy_precision', 0.8);
    config()->set('sast.training.tp_flag_threshold', 0.8);
    config()->set('sast.training.model_path', 'testing/'.Str::uuid().'.rbx');

    $this->modelPath = app(RubixTriageService::class)->modelPath();
});

afterEach(function () {
    ModelState::query()
        ->whereNotNull('model_path')
        ->pluck('model_path')
        ->each(function (string $path) {
            $absolutePath = storage_path('app/'.$path);

            if (file_exists($absolutePath)) {
                unlink($absolutePath);
            }
        });

    if (isset($this->modelPath) && file_exists($this->modelPath)) {
        unlink($this->modelPath);
    }
});

it('reports how far the label set is from being trainable', function () {
    markModelTrainingFindingsTrusted(
        Finding::factory()->count(6)->labeled('true_positive')->create(),
    );
    markModelTrainingFindingsTrusted(
        Finding::factory()->count(4)->labeled('false_positive')->create(),
    );

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

it('requires independently attributable labels for certification data', function () {
    Finding::factory()->labeled('true_positive')->create();

    $pseudo = Finding::factory()->labeled('true_positive')->create();
    TriageFeedback::create([
        'finding_id' => $pseudo->id,
        'user_id' => $this->user->id,
        'corrected_label' => 'true_positive',
        'source' => 'ai_pseudo',
    ]);

    $human = Finding::factory()->labeled('false_positive')->create();
    markModelTrainingFindingTrusted($human, 'human');

    expect(app(RubixTriageService::class)->trainingReadiness())->toMatchArray([
        'total' => 1,
        'true_positive' => 0,
        'false_positive' => 1,
        'ready' => false,
    ]);
});

it('quarantines a trusted label that was flagged for quality review', function () {
    $finding = Finding::factory()->labeled('true_positive')->create();
    markModelTrainingFindingTrusted($finding, 'human');
    $finding->feedback()->update([
        'training_eligible' => false,
        'training_exclusion_reason' => 'The recorded evidence does not match the finding.',
    ]);

    expect(app(RubixTriageService::class)->trainingReadiness())->toMatchArray([
        'total' => 0,
        'true_positive' => 0,
        'false_positive' => 0,
        'ready' => false,
    ]);
});

it('refuses to train below the minimum label count', function () {
    markModelTrainingFindingsTrusted(
        Finding::factory()->count(5)->labeled('true_positive')->create(),
    );
    markModelTrainingFindingsTrusted(
        Finding::factory()->count(5)->labeled('false_positive')->create(),
    );

    app(RubixTriageService::class)->train();
})->throws(InsufficientTrainingDataException::class, 'Insufficient labeled data');

it('refuses to train on a single-class label set', function () {
    // A model fit on one class answers the same label at full confidence for
    // every finding — worse than having no model at all.
    markModelTrainingFindingsTrusted(
        Finding::factory()->count(25)->labeled('true_positive')->create(),
    );

    app(RubixTriageService::class)->train();
})->throws(InsufficientTrainingDataException::class, 'both classes');

it('trains a real model from labeled findings and persists it', function () {
    $service = app(RubixTriageService::class);

    expect($service->hasTrainedModel())->toBeFalse();

    seedSeparableLabels();

    $metrics = $service->train();

    expect($service->hasTrainedModel())->toBeTrue()
        ->and($service->hasCertifiedModel())->toBeTrue()
        ->and($metrics['deployment_status'])->toBe('deployed')
        ->and(file_exists($service->activeModelPath()))->toBeTrue()
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

        expect($finding->predicted_label)->toBeIn(['true_positive', 'false_positive', null])
            ->and($finding->tp_probability)->toBeGreaterThanOrEqual(0.0)->toBeLessThanOrEqual(1.0);

        if ($finding->predicted_label === 'true_positive') {
            expect($finding->tp_probability)->toBeGreaterThanOrEqual(0.8);
        } elseif ($finding->predicted_label === 'false_positive') {
            expect($finding->tp_probability)->toBeLessThanOrEqual(0.15);
        }
    });
});

it('keeps legacy model scores advisory and abstains from automatic labels', function () {
    seedSeparableLabels();
    $service = app(RubixTriageService::class);
    $metrics = $service->train();
    $activePath = storage_path('app/'.$metrics['model_path']);

    copy($activePath, $this->modelPath);
    ModelState::query()->update(['deployment_status' => 'legacy']);

    $finding = Finding::factory()->vectorized()->create();
    expect((new RubixTriageService)->predictBatch([$finding]))->toBe(1);

    $finding->refresh();
    expect($finding->tp_probability)->not->toBeNull()
        ->and($finding->predicted_label)->toBeNull();
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
        ->and($state->deployment_status)->toBe('deployed')
        ->and($state->model_path)->not->toBeNull()
        ->and($state->confusion_matrix)->toHaveKeys(['tp', 'fp', 'fn', 'tn']);
});

it('rejects a project-shifted candidate instead of presenting false confidence', function () {
    seedProjectShiftedLabels();

    $metrics = app(RubixTriageService::class)->train();
    $state = ModelState::sole();

    expect($metrics['deployment_status'])->toBe('rejected')
        ->and($state->deployment_status)->toBe('rejected')
        ->and($state->model_path)->toBeNull()
        ->and($state->evaluation_metadata['rejection_reason'])->not->toBeEmpty()
        ->and(app(RubixTriageService::class)->hasCertifiedModel())->toBeFalse();
});

it('requires true-positive validation evidence from multiple project groups', function () {
    config()->set('sast.training.min_validation_tp_groups', 2);
    seedSeparableLabels();

    $metrics = app(RubixTriageService::class)->train();

    expect($metrics['deployment_status'])->toBe('rejected')
        ->and($metrics['evaluation_metadata']['validation']['true_positive_groups'])->toBe(1)
        ->and($metrics['evaluation_metadata']['rejection_reason'])
        ->toContain('at least 2 are required');
});

it('leaves the certified champion active when a challenger is rejected', function () {
    seedSeparableLabels();
    $service = app(RubixTriageService::class);
    $champion = $service->train();
    $championPath = $service->activeModelPath();

    config()->set('sast.training.min_validation_tp_groups', 2);
    $challenger = $service->train();

    expect($champion['deployment_status'])->toBe('deployed')
        ->and($challenger['deployment_status'])->toBe('rejected')
        ->and($service->activeModelPath())->toBe($championPath)
        ->and(ModelState::where('deployment_status', 'deployed')->count())->toBe(1)
        ->and(ModelState::where('deployment_status', 'rejected')->count())->toBe(1);
});

it('uses a stable grouped dataset fingerprint across repeated evaluations', function () {
    seedSeparableLabels();
    $service = app(RubixTriageService::class);

    $first = $service->train();
    $second = $service->train();

    expect($first['evaluation_metadata']['dataset_fingerprint'])
        ->toBe($second['evaluation_metadata']['dataset_fingerprint'])
        ->and($first['evaluation_metadata']['train'])
        ->toBe($second['evaluation_metadata']['train'])
        ->and($first['evaluation_metadata']['validation'])
        ->toBe($second['evaluation_metadata']['validation'])
        ->and($first['confusion'])->toBe($second['confusion'])
        ->and($first['precision'])->toBe($second['precision']);
});

it('excludes AI pseudo labels from certification data', function () {
    seedSeparableLabels();
    $pseudo = Finding::factory()
        ->for(stableSplitScan(validation: false))
        ->labeled('true_positive')
        ->create();

    TriageFeedback::create([
        'finding_id' => $pseudo->id,
        'user_id' => $this->user->id,
        'corrected_label' => 'true_positive',
        'source' => 'ai_pseudo',
        'notes' => 'AI proposal awaiting independent review.',
    ]);

    $readiness = app(RubixTriageService::class)->trainingReadiness();
    $metrics = app(RubixTriageService::class)->train();

    expect($readiness['total'])->toBe(30)
        ->and($metrics['evaluation_metadata']['pseudo_training_samples'])->toBe(1)
        ->and($metrics['evaluation_metadata']['pseudo_validation_excluded'])->toBe(0)
        ->and($metrics['evaluation_metadata']['train']['samples'])
        ->toBe($metrics['evaluation_metadata']['trusted_train']['samples'] + 1)
        ->and($metrics['evaluation_metadata']['validation']['samples'])
        ->toBe($metrics['sample_size']);
});

it('skips an automatic duplicate training job when no labels changed', function () {
    seedSeparableLabels();

    (new TrainSastModelJob)->handle(app(RubixTriageService::class));
    (new TrainSastModelJob)->handle(app(RubixTriageService::class));

    expect(ModelState::count())->toBe(1);
});

it('runs training jobs queued before the force flag was introduced', function () {
    seedSeparableLabels();
    $legacyJob = new TrainSastModelJob;
    unset($legacyJob->force);

    $legacyJob->handle(app(RubixTriageService::class));

    expect(ModelState::count())->toBe(1);
});

it('treats insufficient data as a skip, not a job failure', function () {
    markModelTrainingFindingsTrusted(
        Finding::factory()->count(3)->labeled('true_positive')->create(),
    );

    (new TrainSastModelJob)->handle(app(RubixTriageService::class));

    expect(ModelState::count())->toBe(0)
        ->and(cache()->has('sast:retrain-lock'))->toBeFalse();
});

it('exposes training status to the dashboard', function () {
    markModelTrainingFindingsTrusted(
        Finding::factory()->count(3)->labeled('true_positive')->create(),
    );
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

    Queue::assertPushedOn(
        'ml-training',
        TrainSastModelJob::class,
        fn (TrainSastModelJob $job) => $job->force,
    );
});

it('blocks a dashboard training run that would fail', function () {
    Queue::fake();
    markModelTrainingFindingsTrusted(
        Finding::factory()->count(3)->labeled('true_positive')->create(),
    );

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
    markModelTrainingFindingsTrusted(
        Finding::factory()->count(3)->labeled('true_positive')->create(),
    );

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
    $trainingScan = stableSplitScan(validation: false);
    $validationScan = stableSplitScan(validation: true);
    $validationPerClass = max(3, (int) floor($perClass * 0.25));

    foreach (range(1, $perClass) as $i) {
        $scan = $i <= $validationPerClass ? $validationScan : $trainingScan;

        $truePositive = Finding::factory()->for($scan)->create([
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

        $falsePositive = Finding::factory()->for($scan)->create([
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

        markModelTrainingFindingTrusted($truePositive);
        markModelTrainingFindingTrusted($falsePositive);
    }
}

function stableSplitScan(bool $validation): Scan
{
    $project = Project::factory()->create();

    for ($nonce = 0; $nonce < 1000; $nonce++) {
        $commit = hash('sha1', ($validation ? 'validation' : 'training').'-'.$nonce);
        $groupHash = hash('sha256', $project->id."\0".strtolower($commit));
        $isValidation = (hexdec(substr($groupHash, 0, 8)) % 100) < 20;

        if ($isValidation === $validation) {
            return Scan::factory()->for($project)->create(['commit_sha' => $commit]);
        }
    }

    throw new RuntimeException('Unable to construct a deterministic model split fixture.');
}

function seedProjectShiftedLabels(int $perClass = 12): void
{
    $trainingScan = stableSplitScan(validation: false);
    $validationScan = stableSplitScan(validation: true);

    foreach (range(1, $perClass) as $i) {
        foreach ([
            [$trainingScan, 'true_positive', 'HIGH', 20 + $i, 0, 0.05],
            [$trainingScan, 'false_positive', 'LOW', 1 + ($i % 2), 1, 0.95],
            // The unseen project has the relationship reversed. A row-level
            // split would leak this project and conceal the failure.
            [$validationScan, 'true_positive', 'LOW', 1 + ($i % 2), 1, 0.95],
            [$validationScan, 'false_positive', 'HIGH', 20 + $i, 0, 0.05],
        ] as [$scan, $label, $severity, $complexity, $isTest, $fpRate]) {
            $finding = Finding::factory()->for($scan)->create([
                'final_label' => $label,
                'status' => 'triaged',
                'severity' => $severity,
                'feature_vector' => [
                    'cwe_id' => $severity === 'HIGH' ? 89 : 79,
                    'scanner_severity' => $severity,
                    'file_extension' => 'php',
                    'is_test_file' => $isTest,
                    'cyclomatic_complexity' => $complexity,
                    'has_sanitizer_in_ast' => $isTest,
                    'line_depth_in_function' => $complexity,
                    'historical_fp_rate_rule' => $fpRate,
                    'developer_experience_lvl' => $isTest ? 'senior' : 'junior',
                ],
            ]);

            markModelTrainingFindingTrusted($finding);
        }
    }
}

function markModelTrainingFindingTrusted(Finding $finding, string $source = 'benchmark'): void
{
    TriageFeedback::query()->updateOrCreate([
        'finding_id' => $finding->id,
    ], [
        'user_id' => User::query()->firstOrFail()->id,
        'corrected_label' => $finding->final_label,
        'source' => $source,
    ]);
}

/** @param iterable<Finding> $findings */
function markModelTrainingFindingsTrusted(iterable $findings, string $source = 'benchmark'): void
{
    foreach ($findings as $finding) {
        markModelTrainingFindingTrusted($finding, $source);
    }
}
