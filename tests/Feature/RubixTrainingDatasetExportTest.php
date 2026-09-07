<?php

use App\Models\Finding;
use App\Models\ModelState;
use App\Models\Project;
use App\Models\Scan;
use App\Models\TriageFeedback;
use App\Models\User;
use App\Services\RubixTriageService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function rubixExportFeatures(array $overrides = []): array
{
    return array_replace([
        'cwe_id' => 89,
        'scanner_severity' => 'HIGH',
        'file_extension' => 'php',
        'is_test_file' => 0,
        'cyclomatic_complexity' => 14,
        'has_sanitizer_in_ast' => 0,
        'line_depth_in_function' => 18,
        'historical_fp_rate_rule' => 0.125,
        'developer_experience_lvl' => 'mid',
    ], $overrides);
}

function rubixExportScan(bool $validation, ?Project $project = null, string $salt = ''): Scan
{
    $project ??= Project::factory()->create();
    $validationPercent = 20;

    for ($nonce = 0; $nonce < 2000; $nonce++) {
        $commit = hash('sha1', "rubix-export-{$salt}-{$nonce}");
        $group = $project->id."\0".strtolower($commit);
        $isValidation = (hexdec(substr(hash('sha256', $group), 0, 8)) % 100)
            < $validationPercent;

        if ($isValidation === $validation) {
            return Scan::factory()->for($project)->complete()->create([
                'commit_sha' => $commit,
            ]);
        }
    }

    throw new RuntimeException('Unable to construct a stable Rubix export split fixture.');
}

/** @param array<string, mixed> $attributes */
function rubixExportFinding(Scan $scan, string $identity, array $attributes = []): Finding
{
    $features = $attributes['feature_vector'] ?? rubixExportFeatures();
    unset($attributes['feature_vector']);

    return Finding::factory()->for($scan)->create(array_replace([
        'rule_id' => 'php.security.sql-injection',
        'cwe_id' => 89,
        'file_path' => "app/Http/Controllers/{$identity}Controller.php",
        'line_number' => 40,
        'severity' => 'HIGH',
        'message' => "Potential SQL injection in {$identity}.",
        'raw_snippet' => "dangerous_sink_{$identity}(\$input);",
        'feature_vector' => $features,
    ], $attributes));
}

function rubixExportLabel(
    Finding $finding,
    User $user,
    string $label,
    string $source,
    ?string $notes = null,
): TriageFeedback {
    $finding->forceFill([
        'final_label' => $label,
        'status' => 'triaged',
    ])->save();

    return TriageFeedback::create([
        'finding_id' => $finding->id,
        'user_id' => $user->id,
        'corrected_label' => $label,
        'source' => $source,
        'notes' => $notes,
    ]);
}

/** @return list<array<string, mixed>> */
function rubixExportJsonl(string $path): array
{
    $payload = Storage::disk('local')->get($path);

    if ($payload === '') {
        return [];
    }

    return array_map(
        static fn (string $line): array => json_decode($line, true, flags: JSON_THROW_ON_ERROR),
        explode("\n", rtrim($payload, "\r\n")),
    );
}

/** @return list<array<string, string|null>> */
function rubixExportCsv(string $path): array
{
    $stream = fopen('php://temp', 'r+');

    if ($stream === false) {
        throw new RuntimeException('Unable to open an in-memory CSV stream.');
    }

    fwrite($stream, Storage::disk('local')->get($path));
    rewind($stream);

    $headers = fgetcsv($stream, escape: '');

    if (! is_array($headers)) {
        fclose($stream);

        return [];
    }

    $rows = [];

    while (($values = fgetcsv($stream, escape: '')) !== false) {
        if ($values === [null]) {
            continue;
        }

        $rows[] = array_combine($headers, $values);
    }

    fclose($stream);

    return $rows;
}

test('export separates trusted labels from quarantine and keeps review labels blank', function () {
    Storage::fake('local');
    Queue::fake();

    $user = User::factory()->create();
    $scan = rubixExportScan(validation: false, salt: 'provenance');

    $human = rubixExportFinding($scan, 'Human', [
        'feature_vector' => rubixExportFeatures(['cyclomatic_complexity' => 21]),
    ]);
    rubixExportLabel($human, $user, 'true_positive', 'human');

    $benchmark = rubixExportFinding($scan, 'Benchmark', [
        'feature_vector' => rubixExportFeatures(['has_sanitizer_in_ast' => 1]),
    ]);
    rubixExportLabel($benchmark, $user, 'false_positive', 'benchmark');

    $import = rubixExportFinding($scan, 'Import', [
        'feature_vector' => rubixExportFeatures(['line_depth_in_function' => 29]),
    ]);
    rubixExportLabel($import, $user, 'true_positive', 'import');

    $pseudo = rubixExportFinding($scan, 'Pseudo');
    rubixExportLabel($pseudo, $user, 'false_positive', 'ai_pseudo');

    $unattributed = rubixExportFinding($scan, 'Legacy', [
        'final_label' => 'true_positive',
        'status' => 'triaged',
    ]);

    $secret = 'abcdefghijklmnop';
    $review = rubixExportFinding($scan, 'Review', [
        'message' => "authorization: Bearer {$secret}",
        'raw_snippet' => "\$api_key = \"{$secret}\";",
        'tp_probability' => 0.91,
    ]);

    $findingsBefore = Finding::query()->orderBy('id')->get()
        ->map(fn (Finding $finding): array => $finding->getAttributes())
        ->all();
    $feedbackBefore = TriageFeedback::query()->orderBy('id')->get()
        ->map(fn (TriageFeedback $feedback): array => $feedback->getAttributes())
        ->all();

    expect(Artisan::call('sast:export-rubix-dataset', [
        '--output' => 'rubix-training/provenance-test',
        '--validation-percent' => '20',
        '--review-limit' => '50',
    ]))->toBe(Command::SUCCESS);

    $directory = 'rubix-training/provenance-test';
    $trusted = [
        ...rubixExportJsonl("{$directory}/train.jsonl"),
        ...rubixExportJsonl("{$directory}/validation.jsonl"),
    ];
    $quarantine = rubixExportJsonl("{$directory}/quarantine.jsonl");
    $reviews = rubixExportJsonl("{$directory}/review_queue.jsonl");
    $reviewCsv = rubixExportCsv("{$directory}/review_queue.csv");

    expect(collect($trusted)->pluck('finding_id')->sort()->values()->all())
        ->toBe(collect([$human->id, $benchmark->id, $import->id])->sort()->values()->all())
        ->and(collect($trusted)->pluck('label_source')->sort()->values()->all())
        ->toBe(['benchmark', 'human', 'import'])
        ->and(collect($trusted)->every(
            fn (array $row): bool => ($row['trusted_for_certification'] ?? false) === true,
        ))->toBeTrue()
        ->and(collect($quarantine)->pluck('finding_id')->sort()->values()->all())
        ->toBe(collect([$pseudo->id, $unattributed->id])->sort()->values()->all())
        ->and(collect($quarantine)->pluck('quarantine_reason')->all())
        ->toContain('ai_pseudo_label', 'unattributed_label')
        ->and(collect($reviews)->pluck('finding_id')->all())->toContain($review->id);

    $reviewRow = collect($reviews)->firstWhere('finding_id', $review->id);
    $reviewCsvRow = collect($reviewCsv)->firstWhere('finding_id', (string) $review->id);

    expect($reviewRow)->toBeArray()
        ->and($reviewRow)->toHaveKeys(['label', 'human_label'])
        ->and($reviewRow['label'] ?? null)->toBeNull()
        ->and($reviewRow['human_label'] ?? null)->toBeIn([null, ''])
        ->and($reviewCsvRow)->toBeArray()
        ->and($reviewCsvRow['human_label'] ?? null)->toBe('')
        ->and(json_encode($reviewRow, JSON_THROW_ON_ERROR))->not->toContain($secret)
        ->and(json_encode($reviewRow, JSON_THROW_ON_ERROR))->toContain('[REDACTED:')
        ->and(Storage::disk('local')->get("{$directory}/review_queue.csv"))->not->toContain($secret);

    $humanRow = collect($trusted)->firstWhere('finding_id', $human->id);

    expect($humanRow)->toBeArray()
        ->and($humanRow['features'])->toBe($human->feature_vector)
        ->and($humanRow['sample'])->toBe(app(RubixTriageService::class)->vectorize($human->feature_vector))
        ->and($humanRow)->toHaveKeys(['fingerprint_sha256', 'group_sha256']);

    expect(Finding::query()->orderBy('id')->get()
        ->map(fn (Finding $finding): array => $finding->getAttributes())
        ->all())->toBe($findingsBefore)
        ->and(TriageFeedback::query()->orderBy('id')->get()
            ->map(fn (TriageFeedback $feedback): array => $feedback->getAttributes())
            ->all())->toBe($feedbackBefore)
        ->and(ModelState::count())->toBe(0);

    Queue::assertNothingPushed();
});

test('export quarantines trusted labels that are awaiting quality review', function () {
    Storage::fake('local');

    $user = User::factory()->create();
    $scan = rubixExportScan(validation: false, salt: 'flagged-label');
    $finding = rubixExportFinding($scan, 'Flagged evidence', [
        'final_label' => 'false_positive',
        'status' => 'triaged',
    ]);
    rubixExportLabel($finding, $user, 'false_positive', 'human');
    $finding->feedback()->update([
        'training_eligible' => false,
        'training_exclusion_reason' => 'Source line no longer matches the stored finding.',
    ]);

    $directory = app(RubixTrainingDatasetExporter::class)->export(
        outputDirectory: 'rubix-training/flagged-label-test',
        validationPercent: 20,
        reviewLimit: 0,
    );
    $rows = rubixExportJsonl("{$directory}/quarantine.jsonl");

    expect($rows)->toHaveCount(1)
        ->and($rows[0]['finding_id'])->toBe($finding->id)
        ->and($rows[0]['quarantine_reason'])->toBe('label_quality_review');
});

test('export deduplicates exact findings and keeps project commit groups in one stable split', function () {
    Storage::fake('local');

    $user = User::factory()->create();
    $project = Project::factory()->create();
    $trainingScan = rubixExportScan(validation: false, project: $project, salt: 'training');
    $validationScan = rubixExportScan(validation: true, project: $project, salt: 'validation');

    foreach (range(1, 3) as $index) {
        $finding = rubixExportFinding($trainingScan, "Training{$index}", [
            'line_number' => 50 + $index,
        ]);
        rubixExportLabel($finding, $user, $index === 1 ? 'true_positive' : 'false_positive', 'human');
    }

    foreach (range(1, 2) as $index) {
        $finding = rubixExportFinding($validationScan, "Validation{$index}", [
            'line_number' => 80 + $index,
        ]);
        rubixExportLabel($finding, $user, $index === 1 ? 'true_positive' : 'false_positive', 'benchmark');
    }

    $duplicateAttributes = [
        'rule_id' => 'php.security.path-traversal',
        'cwe_id' => 22,
        'file_path' => 'app/Http/Controllers/DuplicateController.php',
        'line_number' => 99,
        'message' => 'Repeated scanner result.',
        'raw_snippet' => 'readfile($path);',
        'feature_vector' => rubixExportFeatures(['cwe_id' => 22]),
    ];
    $duplicateOne = rubixExportFinding($trainingScan, 'DuplicateOne', $duplicateAttributes);
    $duplicateTwo = rubixExportFinding($validationScan, 'DuplicateTwo', $duplicateAttributes);
    rubixExportLabel($duplicateOne, $user, 'true_positive', 'human');
    rubixExportLabel($duplicateTwo, $user, 'true_positive', 'human');

    foreach (['first', 'second'] as $run) {
        expect(Artisan::call('sast:export-rubix-dataset', [
            '--output' => "rubix-training/grouped-{$run}",
            '--validation-percent' => '20',
        ]))->toBe(Command::SUCCESS);
    }

    $firstTrain = rubixExportJsonl('rubix-training/grouped-first/train.jsonl');
    $firstValidation = rubixExportJsonl('rubix-training/grouped-first/validation.jsonl');
    $all = [...$firstTrain, ...$firstValidation];

    expect(collect($firstTrain)->pluck('group_sha256')->unique())->toHaveCount(1)
        ->and(collect($firstValidation)->pluck('group_sha256')->unique())->toHaveCount(1)
        ->and(collect($firstTrain)->pluck('group_sha256')->first())
        ->not->toBe(collect($firstValidation)->pluck('group_sha256')->first());

    $duplicateFingerprint = collect($all)
        ->whereIn('finding_id', [$duplicateOne->id, $duplicateTwo->id])
        ->pluck('fingerprint_sha256');

    expect($duplicateFingerprint)->toHaveCount(1)
        ->and(collect($all)->where('fingerprint_sha256', $duplicateFingerprint->first()))->toHaveCount(1)
        ->and(collect($all)->firstWhere('fingerprint_sha256', $duplicateFingerprint->first())['duplicate_count'])
        ->toBe(2);

    foreach (['train.jsonl', 'validation.jsonl', 'review_queue.jsonl', 'review_queue.csv', 'quarantine.jsonl'] as $filename) {
        expect(Storage::disk('local')->get("rubix-training/grouped-second/{$filename}"))
            ->toBe(Storage::disk('local')->get("rubix-training/grouped-first/{$filename}"));
    }

    $firstManifest = json_decode(
        Storage::disk('local')->get('rubix-training/grouped-first/manifest.json'),
        true,
        flags: JSON_THROW_ON_ERROR,
    );
    $secondManifest = json_decode(
        Storage::disk('local')->get('rubix-training/grouped-second/manifest.json'),
        true,
        flags: JSON_THROW_ON_ERROR,
    );

    expect($secondManifest['dataset_fingerprint'])->toBe($firstManifest['dataset_fingerprint']);
});

test('manifest describes the canonical feature schema and verifies every exported file', function () {
    Storage::fake('local');

    $user = User::factory()->create();
    $trainingScan = rubixExportScan(validation: false, salt: 'manifest-train');
    $validationScan = rubixExportScan(validation: true, salt: 'manifest-validation');

    $training = rubixExportFinding($trainingScan, 'ManifestTraining');
    $validation = rubixExportFinding($validationScan, 'ManifestValidation');
    rubixExportLabel($training, $user, 'false_positive', 'human');
    rubixExportLabel($validation, $user, 'true_positive', 'benchmark');
    rubixExportFinding($trainingScan, 'ManifestReview');

    expect(Artisan::call('sast:export-rubix-dataset', [
        '--output' => 'rubix-training/manifest-test',
        '--validation-percent' => '20',
    ]))->toBe(Command::SUCCESS);

    $disk = Storage::disk('local');
    $directory = 'rubix-training/manifest-test';
    $manifest = json_decode(
        $disk->get("{$directory}/manifest.json"),
        true,
        flags: JSON_THROW_ON_ERROR,
    );
    $featureOrder = [
        'cwe_id',
        'scanner_severity',
        'file_extension',
        'is_test_file',
        'cyclomatic_complexity',
        'has_sanitizer_in_ast',
        'line_depth_in_function',
        'historical_fp_rate_rule',
        'developer_experience_lvl',
    ];

    expect($manifest)->toHaveKeys([
        'schema_version',
        'dataset_fingerprint',
        'feature_order',
        'split_strategy',
        'validation_percent',
        'trusted_sources',
        'counts',
        'files',
    ])
        ->and($manifest['feature_order'])->toBe($featureOrder)
        ->and($manifest['validation_percent'])->toBe(20)
        ->and($manifest['trusted_sources'])->toBe(['human', 'benchmark', 'import'])
        ->and($manifest['dataset_fingerprint'])->toMatch('/^[a-f0-9]{64}$/')
        ->and($manifest['counts']['train'])->toBe(1)
        ->and($manifest['counts']['validation'])->toBe(1)
        ->and($manifest['counts']['review_queue'])->toBe(1)
        ->and($manifest['counts']['quarantine'])->toBe(0);

    foreach (['train.jsonl', 'validation.jsonl', 'review_queue.jsonl', 'review_queue.csv', 'quarantine.jsonl'] as $filename) {
        $payload = $disk->get("{$directory}/{$filename}");
        $metadata = $manifest['files'][$filename];

        expect($metadata['path'])->toBe("{$directory}/{$filename}")
            ->and($metadata['bytes'])->toBe(strlen($payload))
            ->and($metadata['sha256'])->toBe(hash('sha256', $payload));
    }
});

test('export rejects unsafe destinations invalid split percentages and invalid review limits', function () {
    Storage::fake('local');

    $invalidInvocations = [
        ['--output' => '../outside'],
        ['--output' => '/outside'],
        ['--output' => 'C:\\outside'],
        ['--output' => '\\\\server\\share'],
        ['--output' => 'rubix-training/./outside'],
        ['--validation-percent' => '0'],
        ['--validation-percent' => '51'],
        ['--validation-percent' => 'not-an-integer'],
        ['--review-limit' => '-1'],
        ['--review-limit' => 'not-an-integer'],
    ];

    foreach ($invalidInvocations as $options) {
        expect(Artisan::call('sast:export-rubix-dataset', $options))->toBe(Command::FAILURE);
    }

    expect(Storage::disk('local')->allFiles())->toBeEmpty();
});

test('export refuses to overwrite an existing dataset directory', function () {
    Storage::fake('local');

    $disk = Storage::disk('local');
    $disk->put('rubix-training/existing/keep.txt', 'do not replace');

    expect(Artisan::call('sast:export-rubix-dataset', [
        '--output' => 'rubix-training/existing',
    ]))->toBe(Command::FAILURE)
        ->and($disk->get('rubix-training/existing/keep.txt'))->toBe('do not replace')
        ->and($disk->allFiles('rubix-training/existing'))->toBe([
            'rubix-training/existing/keep.txt',
        ]);
});
