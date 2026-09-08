<?php

namespace App\Services;

use App\Exceptions\InsufficientTrainingDataException;
use App\Models\Finding;
use App\Models\ModelState;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Rubix\ML\Classifiers\ClassificationTree;
use Rubix\ML\Classifiers\RandomForest;
use Rubix\ML\Datasets\Labeled;
use Rubix\ML\Datasets\Unlabeled;
use Rubix\ML\PersistentModel;
use Rubix\ML\Persisters\Filesystem;
use Rubix\ML\Pipeline;
use Rubix\ML\Transformers\OneHotEncoder;
use Rubix\ML\Transformers\ZScaleStandardizer;

/**
 * Central inference + training engine. Wraps a Rubix ML Pipeline
 * (OneHotEncoder + ZScaleStandardizer -> RandomForest) behind a
 * PersistentModel so trained weights survive across requests/queue jobs.
 *
 * @phpstan-type RubixDatasetRow array{
 *   finding_id:int,
 *   scan_id:int,
 *   project_id:int,
 *   scanner_source:string,
 *   commit_sha:string,
 *   rule_id:string,
 *   cwe_id:?int,
 *   file_path:string,
 *   line_number:int,
 *   severity:string,
 *   label_source:string,
 *   fingerprint:string,
 *   group_key:string,
 *   label:string,
 *   features:array<string,mixed>,
 *   sample:list<string|int|float|null>,
 *   feature_sha256:string,
 *   duplicate_count:int,
 *   ambiguous_feature:bool
 * }
 */
class RubixTriageService
{
    private const MODEL_PATH = 'sast_triage_model.rbx';

    private const VALIDATION_STRATEGY = 'project_commit_hash_v1';

    private const FEATURE_SCHEMA_VERSION = 'source-dataflow-v2';

    // Models created before source-local dataflow features were activated must
    // continue to receive exactly the nine columns they were trained on.
    private const LEGACY_FEATURE_ORDER = [
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

    // Order matters: it is fingerprinted into every new model and dataset.
    // These four fields already exist on most historical vectors, but were
    // accidentally omitted from Rubix's sample. Missing evidence has an
    // explicit sentinel so it cannot be mistaken for a proven-safe flow.
    private const FEATURE_ORDER = [
        ...self::LEGACY_FEATURE_ORDER,
        'reaches_request_input',
        'taint_steps',
        'sanitised_before_sink',
        'attacker_reachable_context',
    ];

    private ?PersistentModel $model = null;

    private ?string $loadedModelPath = null;

    /**
     * Build the raw ordered feature row Rubix expects from a finding's
     * associative feature vector (as produced by AstFeatureExtractor
     * + rule history + scanner metadata).
     *
     * @param  array<string, mixed>  $featureVector
     * @param  list<string>|null  $featureOrder
     * @return list<string|int|float|null>
     */
    public function vectorize(array $featureVector, ?array $featureOrder = null): array
    {
        $featureOrder ??= self::FEATURE_ORDER;

        return array_map(
            fn (string $key) => $this->normalizedFeature(
                $key,
                $featureVector[$key] ?? $this->defaultFor($key),
            ),
            $featureOrder,
        );
    }

    /** @return list<string> */
    public function featureOrder(): array
    {
        return self::FEATURE_ORDER;
    }

    /**
     * Stable identity used to collapse the same scanner hit across repeated
     * scans. This is public so dataset exports and model training cannot drift
     * into using subtly different duplicate definitions.
     */
    public function findingFingerprint(Finding $finding): string
    {
        $snippet = preg_replace('/\s+/', ' ', trim((string) $finding->raw_snippet)) ?? '';

        return hash('sha256', implode("\0", [
            (string) $finding->rule_id,
            (string) $finding->cwe_id,
            str_replace('\\', '/', (string) $finding->file_path),
            (string) $finding->line_number,
            $snippet !== '' ? $snippet : trim((string) $finding->message),
        ]));
    }

    /**
     * Project and commit are the smallest honest independence boundary we
     * currently have. A blank commit falls back to its scan rather than
     * merging unrelated uploads into one anonymous group.
     */
    public function findingGroupKey(Finding $finding): string
    {
        $commit = strtolower(trim((string) $finding->scan?->commit_sha));
        $groupKey = (string) $finding->scan?->project_id."\0".$commit;

        if ($commit === '') {
            $groupKey .= "\0scan:".(string) $finding->scan_id;
        }

        return $groupKey;
    }

    private function defaultFor(string $key): string|int|float|null
    {
        return match ($key) {
            'cwe_id', 'cyclomatic_complexity', 'line_depth_in_function' => 0,
            'is_test_file', 'has_sanitizer_in_ast' => 0,
            'historical_fp_rate_rule' => 0.0,
            'reaches_request_input', 'sanitised_before_sink' => -1,
            'taint_steps' => -2,
            'scanner_severity' => 'MEDIUM',
            'file_extension' => 'php',
            'developer_experience_lvl' => 'unknown',
            'attacker_reachable_context' => 'unknown',
            default => null,
        };
    }

    private function normalizedFeature(string $key, mixed $value): string|int|float|null
    {
        return match ($key) {
            'cwe_id', 'cyclomatic_complexity', 'line_depth_in_function',
            'is_test_file', 'has_sanitizer_in_ast', 'reaches_request_input',
            'taint_steps', 'sanitised_before_sink' => is_numeric($value)
                ? (int) $value
                : (int) $this->defaultFor($key),
            'historical_fp_rate_rule' => is_numeric($value) ? (float) $value : 0.0,
            'scanner_severity' => strtoupper(trim((string) $value)) ?: 'MEDIUM',
            'file_extension', 'developer_experience_lvl', 'attacker_reachable_context' => strtolower(trim((string) $value)) ?: (string) $this->defaultFor($key),
            default => match (true) {
                is_bool($value) => (int) $value,
                is_int($value), is_float($value), is_string($value), $value === null => $value,
                default => null,
            },
        };
    }

    /**
     * Whether a trained model has been persisted yet. Callers use this to
     * decide whether inference is possible at all — before the first
     * training run the app is still in its cold-start phase, where scans
     * are ingested and vectorized but findings go straight to the human
     * triage queue unscored.
     */
    public function hasTrainedModel(): bool
    {
        return $this->modelRuntime() !== null;
    }

    /**
     * A certified model passed the leakage-resistant validation gate. Legacy
     * model files may still provide an advisory score, but they must not
     * produce automatic TP/FP labels.
     */
    public function hasCertifiedModel(): bool
    {
        return ($this->modelRuntime()['certified'] ?? false) === true;
    }

    /**
     * Predict True Positive probability for a single Finding.
     * Persists the score and predicted_label back onto the model.
     */
    public function predictFinding(Finding $finding): Finding
    {
        $runtime = $this->modelRuntime();

        if ($runtime === null) {
            throw new \RuntimeException(
                'No trained model found. Run the training job first (php artisan sast:train).'
            );
        }

        $probabilities = $this->probabilitiesFor(
            [$this->vectorize($finding->feature_vector ?? [], $runtime['feature_order'])],
            $runtime,
        )[0] ?? [];

        $this->applyPrediction($finding, $probabilities, $runtime);
        $finding->save();

        return $finding;
    }

    /**
     * Batch prediction, used by the ingestion pipeline after a full scan
     * has been parsed and feature-vectorized. Far more efficient than
     * calling predictFinding() in a loop because the model is loaded once
     * and Rubix predicts over the whole dataset in a single pass.
     *
     * @param  iterable<Finding>  $findings
     * @return int Number of findings scored (0 during cold start).
     */
    public function predictBatch(iterable $findings): int
    {
        $findingsArray = is_array($findings) ? $findings : iterator_to_array($findings);

        if (empty($findingsArray)) {
            return 0;
        }

        $runtime = $this->modelRuntime();

        if ($runtime === null) {
            // Cold start: no model yet. Leave predicted_label/tp_probability
            // null so the triage UI shows these as unscored rather than
            // presenting a fabricated confidence, and so the ingestion
            // pipeline still completes and produces labelable rows.
            return 0;
        }

        $samples = array_values(array_map(
            fn (Finding $f) => $this->vectorize(
                $f->feature_vector ?? [],
                $runtime['feature_order'],
            ),
            $findingsArray
        ));
        $probabilities = $this->probabilitiesFor($samples, $runtime);

        foreach (array_values($findingsArray) as $i => $finding) {
            $this->applyPrediction($finding, $probabilities[$i] ?? [], $runtime);
            $finding->save();
        }

        return count($findingsArray);
    }

    /**
     * Run one inference pass and return the per-class probabilities.
     *
     * Deliberately calls proba() only — Rubix's Pipeline transforms the
     * Dataset *in place*, so calling predict() and then proba() on the same
     * Dataset instance runs the samples through OneHotEncoder and
     * ZScaleStandardizer twice and blows up on a dimensionality mismatch.
     * The deployment decision is derived from these probabilities at the
     * certified threshold. Rubix RandomForest::predict() uses hard per-tree
     * majority votes instead, so evaluating it would not measure the same
     * behavior that production serves.
     *
     * @param  list<list<mixed>>  $samples
     * @param  array{path:string,certified:bool,tp_threshold:float,fp_threshold:float,feature_order:list<string>}  $runtime
     * @return list<array<string, float>>
     */
    private function probabilitiesFor(array $samples, array $runtime): array
    {
        return $this->loadModel($runtime['path'])->proba(new Unlabeled($samples));
    }

    /**
     * @param  array<string, float>  $probabilities
     * @param  array{path:string,certified:bool,tp_threshold:float,fp_threshold:float,feature_order:list<string>}  $runtime
     */
    private function applyPrediction(Finding $finding, array $probabilities, array $runtime): void
    {
        $tpProbability = (float) ($probabilities['true_positive'] ?? 0.0);

        $finding->predicted_label = match (true) {
            ! $runtime['certified'] => null,
            $tpProbability >= $runtime['tp_threshold'] => 'true_positive',
            $tpProbability <= $runtime['fp_threshold'] => 'false_positive',
            default => null,
        };
        $finding->tp_probability = round($tpProbability, 4);
        $finding->status = 'pending'; // awaiting human triage or auto-suppression rule
    }

    /**
     * How many human-confirmed labels are currently available to train on,
     * and how they split across the two classes. Used by the training
     * command/dashboard to tell a user how far they are from being able
     * to train, without attempting a run that will just throw.
     *
     * @return array{total:int, true_positive:int, false_positive:int, required:int, ready:bool}
     */
    public function trainingReadiness(): array
    {
        $counts = $this->trustedTrainingQuery()
            ->selectRaw('final_label, count(*) as aggregate')
            ->groupBy('final_label')
            ->pluck('aggregate', 'final_label');

        $truePositive = (int) $counts->get('true_positive', 0);
        $falsePositive = (int) $counts->get('false_positive', 0);
        $required = $this->minimumTrainingSamples();
        $total = $truePositive + $falsePositive;

        return [
            'total' => $total,
            'true_positive' => $truePositive,
            'false_positive' => $falsePositive,
            'required' => $required,
            'ready' => $total >= $required && $truePositive > 0 && $falsePositive > 0,
        ];
    }

    /**
     * Return the exact deduplicated, grouped data seen by model training.
     * The exporter consumes this snapshot rather than reimplementing Rubix's
     * split logic, making offline datasets reproducible and leakage-resistant.
     *
     * @return array{
     *   dataset_fingerprint:string,
     *   feature_order:list<string>,
     *   train:list<RubixDatasetRow>,
     *   validation:list<RubixDatasetRow>,
     *   statistics:array<string,mixed>
     * }
     */
    public function trainingDatasetSnapshot(int $validationPercent): array
    {
        if ($validationPercent < 1 || $validationPercent > 50) {
            throw new InvalidArgumentException('Validation percent must be between 1 and 50.');
        }

        $prepared = $this->preparedTrustedRows();
        [$trainingRows, $validationRows] = $this->splitByProjectCommit(
            $prepared['rows'],
            $validationPercent,
        );

        return [
            'dataset_fingerprint' => $prepared['dataset_fingerprint'],
            'feature_order' => self::FEATURE_ORDER,
            'train' => $trainingRows,
            'validation' => $validationRows,
            'statistics' => [
                'total' => $this->rowCounts($prepared['rows']),
                'train' => $this->rowCounts($trainingRows),
                'validation' => $this->rowCounts($validationRows),
                'excluded_duplicates' => $prepared['excluded_duplicates'],
                'excluded_conflicts' => $prepared['excluded_conflicts'],
                'excluded_inconsistent_labels' => $prepared['excluded_inconsistent_labels'],
                'ambiguous_feature_rows' => $prepared['ambiguous_feature_rows'],
                'ambiguous_feature_vectors' => $prepared['ambiguous_feature_vectors'],
            ],
        ];
    }

    /**
     * Train (or retrain) the model from all confirmed triage feedback
     * (findings with a non-null final_label). Called from
     * TrainSastModelJob, never synchronously from a web request.
     *
     * A candidate is evaluated on complete project+commit groups and saved
     * only if it clears the configured precision/support gate. Rejected
     * candidates are audited in model_states and never replace the active
     * model.
     *
     * @return array<string, mixed>
     *
     * @throws InsufficientTrainingDataException
     */
    public function train(): array
    {
        $readiness = $this->trainingReadiness();

        if ($readiness['total'] < $readiness['required']) {
            throw new InsufficientTrainingDataException(sprintf(
                'Insufficient labeled data to train: %d rows (minimum %d). Triage more findings first.',
                $readiness['total'],
                $readiness['required'],
            ));
        }

        // A single-class dataset trains "successfully" but yields a model that
        // answers the same label at 100% confidence for every finding, which
        // would silently poison every downstream prediction.
        if ($readiness['true_positive'] === 0 || $readiness['false_positive'] === 0) {
            throw new InsufficientTrainingDataException(sprintf(
                'Training needs both classes represented: %d true positives, %d false positives.',
                $readiness['true_positive'],
                $readiness['false_positive'],
            ));
        }

        $prepared = $this->preparedTrustedRows();
        $rows = $prepared['rows'];

        if (count($rows) < $readiness['required']) {
            throw new InsufficientTrainingDataException(sprintf(
                'Only %d unique, conflict-free labeled findings remain after deduplication (minimum %d).',
                count($rows),
                $readiness['required'],
            ));
        }

        [$trainingRows, $validationRows] = $this->splitByProjectCommit(
            $rows,
            (int) config('sast.training.validation_percent', 20),
        );
        $trustedTrainingCounts = $this->rowCounts($trainingRows);
        $validationCounts = $this->rowCounts($validationRows);

        $this->assertUsablePartition('training', $trustedTrainingCounts);
        $this->assertUsablePartition('validation', $validationCounts);

        $pseudoPrepared = $this->prepareTrainingRows(
            $this->pseudoTrainingQuery()
                ->with([
                    'scan:id,project_id,source,commit_sha',
                    'feedback:id,finding_id,corrected_label,source',
                ])
                ->orderBy('id')
                ->get()
        );
        [$pseudoTrainingRows, $pseudoValidationRows] = $this->splitByProjectCommit(
            $pseudoPrepared['rows'],
            (int) config('sast.training.validation_percent', 20),
        );
        $trustedFingerprints = array_fill_keys(array_column($rows, 'fingerprint'), true);
        $pseudoBeforeDedupe = count($pseudoTrainingRows);
        $pseudoTrainingRows = array_values(array_filter(
            $pseudoTrainingRows,
            static fn (array $row): bool => ! isset($trustedFingerprints[$row['fingerprint']]),
        ));
        $pseudoDuplicateExclusions = $pseudoBeforeDedupe - count($pseudoTrainingRows);
        [$pseudoTrainingRows, $pseudoCapped] = $this->capPseudoRows(
            $pseudoTrainingRows,
            $trustedTrainingCounts,
        );
        $trainingRows = [...$trainingRows, ...$pseudoTrainingRows];
        $trainingCounts = $this->rowCounts($trainingRows);
        $datasetFingerprint = hash('sha256', json_encode([
            $prepared['dataset_fingerprint'],
            array_map(
                static fn (array $row): array => [$row['fingerprint'], $row['label'], $row['sample']],
                $pseudoTrainingRows,
            ),
        ], JSON_THROW_ON_ERROR));

        $training = new Labeled(
            array_column($trainingRows, 'sample'),
            array_column($trainingRows, 'label'),
        );
        $testing = new Unlabeled(array_column($validationRows, 'sample'));
        $actual = array_column($validationRows, 'label');

        $randomSeed = (int) hexdec(substr($datasetFingerprint, 0, 8));
        srand($randomSeed);
        $estimator = $this->newEstimator();

        $estimator->train($training);

        $threshold = $this->tpFlagThreshold();
        $probabilities = $estimator->proba($testing);
        $predictions = array_map(
            static fn (array $joint): string => (float) ($joint['true_positive'] ?? 0.0) >= $threshold
                ? 'true_positive'
                : 'false_positive',
            $probabilities,
        );

        $metrics = $this->scoreModel($predictions, $actual);
        $metrics['trained_on'] = $training->numSamples();
        $metrics['flagged_count'] = $metrics['confusion']['tp'] + $metrics['confusion']['fp'];
        $metrics['precision_defined'] = $metrics['flagged_count'] > 0;

        $metadata = [
            'strategy' => self::VALIDATION_STRATEGY,
            'feature_schema_version' => self::FEATURE_SCHEMA_VERSION,
            'feature_order' => self::FEATURE_ORDER,
            'feature_schema_sha256' => hash(
                'sha256',
                json_encode([self::FEATURE_SCHEMA_VERSION, self::FEATURE_ORDER], JSON_THROW_ON_ERROR),
            ),
            'dataset_fingerprint' => $datasetFingerprint,
            'random_seed' => $randomSeed,
            'excluded_duplicates' => $prepared['excluded_duplicates'],
            'excluded_conflicts' => $prepared['excluded_conflicts'],
            'excluded_inconsistent_labels' => $prepared['excluded_inconsistent_labels'],
            'ambiguous_feature_rows' => $prepared['ambiguous_feature_rows'],
            'ambiguous_feature_vectors' => $prepared['ambiguous_feature_vectors'],
            'trusted_train' => $trustedTrainingCounts,
            'train' => $trainingCounts,
            'validation' => $validationCounts,
            'pseudo_training_samples' => count($pseudoTrainingRows),
            'pseudo_validation_excluded' => count($pseudoValidationRows),
            'pseudo_duplicate_excluded' => $pseudoDuplicateExclusions,
            'pseudo_capped' => $pseudoCapped,
            'flagged_count' => $metrics['flagged_count'],
            'coverage' => round($metrics['flagged_count'] / max(1, $metrics['sample_size']), 4),
            'precision_defined' => $metrics['precision_defined'],
            'min_precision' => $this->minimumDeployPrecision(),
            'min_flags' => $this->minimumDeployFlags(),
            'min_validation_tp_groups' => max(
                1,
                (int) config('sast.training.min_validation_tp_groups', 2),
            ),
        ];

        $rejectionReason = $this->qualityGateRejection($metrics, $validationCounts);
        $deploymentStatus = $rejectionReason === null ? 'deployed' : 'rejected';
        $relativeModelPath = null;

        if ($deploymentStatus === 'deployed') {
            $relativeModelPath = $this->candidateModelPath($datasetFingerprint);
            $absoluteModelPath = $this->absoluteStoragePath($relativeModelPath);

            if (! is_dir(dirname($absoluteModelPath))) {
                mkdir(dirname($absoluteModelPath), 0755, true);
            }

            (new PersistentModel($estimator, new Filesystem($absoluteModelPath)))->save();
        } else {
            $metadata['rejection_reason'] = $rejectionReason;
        }

        try {
            ModelState::create([
                'trained_at' => now(),
                'sample_size' => $metrics['sample_size'],
                'precision' => $metrics['precision'],
                'recall' => $metrics['recall'],
                'f1_score' => $metrics['f1_score'],
                'confusion_matrix' => $metrics['confusion'],
                'deployment_status' => $deploymentStatus,
                'decision_threshold' => $threshold,
                'model_path' => $relativeModelPath,
                'evaluation_metadata' => $metadata,
            ]);
        } catch (\Throwable $e) {
            if ($relativeModelPath !== null) {
                @unlink($this->absoluteStoragePath($relativeModelPath));
            }

            throw $e;
        }

        $metrics['deployment_status'] = $deploymentStatus;
        $metrics['decision_threshold'] = $threshold;
        $metrics['model_path'] = $relativeModelPath;
        $metrics['evaluation_metadata'] = $metadata;

        // A long-running queue worker may already have the previous version
        // in memory. Force path resolution/reload after every attempt.
        $this->model = null;
        $this->loadedModelPath = null;

        return $metrics;
    }

    /**
     * Compute precision/recall/F1 for the 'true_positive' class on the
     * held-out test split. Kept dependency-free (no rubix Reports needed)
     * so it's easy to log/store in model_states.
     */
    /**
     * @param  list<string>  $predictions
     * @param  list<string>  $actual
     * @return array{sample_size:int, precision:float, recall:float, f1_score:float, confusion:array{tp:int, fp:int, fn:int, tn:int}}
     */
    private function scoreModel(array $predictions, array $actual): array
    {
        $tp = $fp = $fn = $tn = 0;

        foreach ($predictions as $i => $predicted) {
            $truth = $actual[$i];
            if ($predicted === 'true_positive' && $truth === 'true_positive') {
                $tp++;
            } elseif ($predicted === 'true_positive' && $truth === 'false_positive') {
                $fp++;
            } elseif ($predicted === 'false_positive' && $truth === 'true_positive') {
                $fn++;
            } else {
                $tn++;
            }
        }

        $precision = ($tp + $fp) > 0 ? $tp / ($tp + $fp) : 0.0;
        $recall = ($tp + $fn) > 0 ? $tp / ($tp + $fn) : 0.0;
        $f1 = ($precision + $recall) > 0 ? 2 * ($precision * $recall) / ($precision + $recall) : 0.0;

        return [
            'sample_size' => count($predictions),
            'precision' => round($precision, 4),
            'recall' => round($recall, 4),
            'f1_score' => round($f1, 4),
            'confusion' => ['tp' => $tp, 'fp' => $fp, 'fn' => $fn, 'tn' => $tn],
        ];
    }

    /** @return Builder<Finding> */
    private function trustedTrainingQuery(): Builder
    {
        return Finding::query()
            ->whereNotNull('final_label')
            ->whereNotNull('feature_vector')
            // Certification evidence must be traceable to an independent
            // decision. Orphan/demo labels and AI proposals stay out even if
            // somebody populated findings.final_label directly.
            ->whereHas('feedback', fn (Builder $query) => $query
                ->whereIn('source', ['human', 'benchmark', 'import'])
                ->where('training_eligible', true)
                ->whereColumn('triage_feedback.corrected_label', 'findings.final_label'));
    }

    /** @return Builder<Finding> */
    private function pseudoTrainingQuery(): Builder
    {
        return Finding::query()
            ->whereNotNull('final_label')
            ->whereNotNull('feature_vector')
            ->whereHas('feedback', fn (Builder $query) => $query
                ->where('source', 'ai_pseudo')
                ->where('training_eligible', true));
    }

    /**
     * @return array{
     *   rows:list<RubixDatasetRow>,
     *   dataset_fingerprint:string,
     *   excluded_duplicates:int,
     *   excluded_conflicts:int,
     *   excluded_inconsistent_labels:int,
     *   ambiguous_feature_rows:int,
     *   ambiguous_feature_vectors:int
     * }
     */
    private function preparedTrustedRows(): array
    {
        return $this->prepareTrainingRows(
            $this->trustedTrainingQuery()
                ->with([
                    'scan:id,project_id,source,commit_sha',
                    'feedback:id,finding_id,corrected_label,source,training_eligible,training_exclusion_reason',
                ])
                ->orderBy('id')
                ->get(),
        );
    }

    /**
     * Weak labels can augment only the training side and cannot dominate
     * either human class. Their project groups are still excluded from the
     * independent validation side, which always remains human/benchmark data.
     *
     * @param  list<RubixDatasetRow>  $rows
     * @param  array{true_positive:int,false_positive:int}  $trustedCounts
     * @return array{0:list<RubixDatasetRow>,1:int}
     */
    private function capPseudoRows(array $rows, array $trustedCounts): array
    {
        $ratio = min(0.5, max(0.0, (float) config('sast.training.max_pseudo_ratio_per_class', 0.25)));
        $limits = [
            'true_positive' => (int) floor($trustedCounts['true_positive'] * $ratio),
            'false_positive' => (int) floor($trustedCounts['false_positive'] * $ratio),
        ];
        $used = ['true_positive' => 0, 'false_positive' => 0];
        $included = [];

        foreach ($rows as $row) {
            $label = $row['label'];

            if (! isset($limits[$label]) || $used[$label] >= $limits[$label]) {
                continue;
            }

            $included[] = $row;
            $used[$label]++;
        }

        return [$included, count($rows) - count($included)];
    }

    /**
     * Collapse exact repeated scanner findings before splitting. Repeated
     * scans of the same code must not let one copy train the model while a
     * second copy makes validation look artificially strong. Any exact
     * fingerprint carrying contradictory labels is excluded entirely.
     *
     * @param  Collection<int, Finding>  $findings
     * @return array{
     *   rows:list<RubixDatasetRow>,
     *   dataset_fingerprint:string,
     *   excluded_duplicates:int,
     *   excluded_conflicts:int,
     *   excluded_inconsistent_labels:int,
     *   ambiguous_feature_rows:int,
     *   ambiguous_feature_vectors:int
     * }
     */
    private function prepareTrainingRows(Collection $findings): array
    {
        $buckets = [];
        $excludedInconsistentLabels = 0;

        foreach ($findings as $finding) {
            if (! in_array($finding->final_label, ['true_positive', 'false_positive'], true)) {
                continue;
            }

            $feedback = $finding->feedback;

            // A partially failed or manually edited import can leave the two
            // canonical label columns disagreeing. Silently choosing either
            // side would teach Rubix a label nobody actually asserted.
            if (
                $feedback !== null
                && ! hash_equals((string) $finding->final_label, (string) $feedback->corrected_label)
            ) {
                $excludedInconsistentLabels++;

                continue;
            }

            $features = is_array($finding->feature_vector)
                ? $finding->feature_vector
                : [];

            $sample = $this->vectorize($features);
            $fingerprint = $this->findingFingerprint($finding);
            $groupKey = $this->findingGroupKey($finding);

            $buckets[$fingerprint][] = [
                'id' => (int) $finding->getKey(),
                'finding_id' => (int) $finding->getKey(),
                'scan_id' => (int) $finding->scan_id,
                'project_id' => (int) $finding->scan->project_id,
                'scanner_source' => (string) $finding->scan->source,
                'commit_sha' => strtolower(trim((string) $finding->scan->commit_sha)),
                'rule_id' => (string) $finding->rule_id,
                'cwe_id' => $finding->cwe_id === null ? null : (int) $finding->cwe_id,
                'file_path' => str_replace('\\', '/', (string) $finding->file_path),
                'line_number' => (int) $finding->line_number,
                'severity' => (string) $finding->severity,
                'label_source' => (string) ($feedback->source ?? 'unattributed'),
                'fingerprint' => $fingerprint,
                'group_key' => $groupKey,
                'label' => (string) $finding->final_label,
                'features' => $features,
                'sample' => $sample,
                'feature_sha256' => hash('sha256', json_encode($sample, JSON_THROW_ON_ERROR)),
                'duplicate_count' => 0,
                'ambiguous_feature' => false,
            ];
        }

        $rows = [];
        $excludedDuplicates = 0;
        $excludedConflicts = 0;

        foreach ($buckets as $candidates) {
            $labels = array_values(array_unique(array_column($candidates, 'label')));

            if (count($labels) !== 1) {
                $excludedConflicts += count($candidates);

                continue;
            }

            usort($candidates, static fn (array $left, array $right): int => [
                $left['group_key'],
                json_encode($left['sample']),
                $left['id'],
            ] <=> [
                $right['group_key'],
                json_encode($right['sample']),
                $right['id'],
            ]);

            $representative = $candidates[0];
            unset($representative['id']);
            $representative['duplicate_count'] = count($candidates);
            $rows[] = $representative;
            $excludedDuplicates += count($candidates) - 1;
        }

        usort($rows, static fn (array $left, array $right): int => [
            $left['fingerprint'],
            $left['label'],
        ] <=> [
            $right['fingerprint'],
            $right['label'],
        ]);

        $featureBuckets = [];

        foreach ($rows as $row) {
            $featureBuckets[$row['feature_sha256']][] = $row['label'];
        }

        $ambiguousFeatureRows = 0;
        $ambiguousFeatureVectors = 0;
        $ambiguousFeatureHashes = [];

        foreach ($featureBuckets as $featureHash => $labels) {
            if (count(array_unique($labels)) > 1) {
                $ambiguousFeatureVectors++;
                $ambiguousFeatureRows += count($labels);
                $ambiguousFeatureHashes[$featureHash] = true;
            }
        }

        $rows = array_map(
            static function (array $row) use ($ambiguousFeatureHashes): array {
                $row['ambiguous_feature'] = isset($ambiguousFeatureHashes[$row['feature_sha256']]);

                return $row;
            },
            $rows,
        );

        $fingerprintPayload = array_map(
            static fn (array $row): array => [
                $row['fingerprint'],
                $row['group_key'],
                $row['label'],
                $row['sample'],
            ],
            $rows,
        );

        return [
            'rows' => $rows,
            'dataset_fingerprint' => hash('sha256', json_encode($fingerprintPayload, JSON_THROW_ON_ERROR)),
            'excluded_duplicates' => $excludedDuplicates,
            'excluded_conflicts' => $excludedConflicts,
            'excluded_inconsistent_labels' => $excludedInconsistentLabels,
            'ambiguous_feature_rows' => $ambiguousFeatureRows,
            'ambiguous_feature_vectors' => $ambiguousFeatureVectors,
        ];
    }

    /**
     * @param  list<RubixDatasetRow>  $rows
     * @return array{0:list<RubixDatasetRow>,1:list<RubixDatasetRow>}
     */
    private function splitByProjectCommit(array $rows, int $validationPercent): array
    {
        $validationPercent = min(50, max(1, $validationPercent));
        $training = [];
        $validation = [];

        foreach ($rows as $row) {
            $groupHash = hash('sha256', $row['group_key']);
            $bucket = hexdec(substr($groupHash, 0, 8)) % 100;

            if ($bucket < $validationPercent) {
                $validation[] = $row;
            } else {
                $training[] = $row;
            }
        }

        return [$training, $validation];
    }

    /**
     * @param  list<RubixDatasetRow>  $rows
     * @return array{samples:int,true_positive:int,false_positive:int,groups:int,true_positive_groups:int}
     */
    private function rowCounts(array $rows): array
    {
        $labels = array_count_values(array_column($rows, 'label'));
        $groups = [];
        $positiveGroups = [];

        foreach ($rows as $row) {
            $groups[$row['group_key']] = true;

            if ($row['label'] === 'true_positive') {
                $positiveGroups[$row['group_key']] = true;
            }
        }

        return [
            'samples' => count($rows),
            'true_positive' => (int) ($labels['true_positive'] ?? 0),
            'false_positive' => (int) ($labels['false_positive'] ?? 0),
            'groups' => count($groups),
            'true_positive_groups' => count($positiveGroups),
        ];
    }

    /** @param array{samples:int,true_positive:int,false_positive:int} $counts */
    private function assertUsablePartition(string $name, array $counts): void
    {
        if ($counts['samples'] === 0 || $counts['true_positive'] === 0 || $counts['false_positive'] === 0) {
            throw new InsufficientTrainingDataException(sprintf(
                'The stable %s partition needs both classes: %d true positives / %d false positives.',
                $name,
                $counts['true_positive'],
                $counts['false_positive'],
            ));
        }
    }

    private function newEstimator(): Pipeline
    {
        return new Pipeline([
            new OneHotEncoder,
            new ZScaleStandardizer,
        ], new RandomForest(
            new ClassificationTree((int) config('sast.forest.max_tree_depth', 10)),
            (int) config('sast.forest.estimators', 100),
            (float) config('sast.forest.bagging_ratio', 0.5),
            (bool) config('sast.forest.balanced', true),
        ));
    }

    /**
     * @param  array<string, mixed>  $metrics
     * @param  array{true_positive:int,true_positive_groups:int}  $validationCounts
     */
    private function qualityGateRejection(array $metrics, array $validationCounts): ?string
    {
        $minimumValidationPositives = max(
            1,
            (int) config('sast.training.min_validation_true_positives', 5),
        );
        $minimumValidationPositiveGroups = max(
            1,
            (int) config('sast.training.min_validation_tp_groups', 2),
        );
        $reasons = [];

        if ($validationCounts['true_positive'] < $minimumValidationPositives) {
            $reasons[] = sprintf(
                'Validation contains only %d true positives; at least %d are required.',
                $validationCounts['true_positive'],
                $minimumValidationPositives,
            );
        }

        if ($validationCounts['true_positive_groups'] < $minimumValidationPositiveGroups) {
            $reasons[] = sprintf(
                'Validation true positives cover only %d project group%s; at least %d are required.',
                $validationCounts['true_positive_groups'],
                $validationCounts['true_positive_groups'] === 1 ? '' : 's',
                $minimumValidationPositiveGroups,
            );
        }

        if ($metrics['flagged_count'] < $this->minimumDeployFlags()) {
            $reasons[] = sprintf(
                'Candidate flagged only %d validation findings; at least %d are required.',
                $metrics['flagged_count'],
                $this->minimumDeployFlags(),
            );
        }

        if ($metrics['precision_defined'] && $metrics['precision'] < $this->minimumDeployPrecision()) {
            $reasons[] = sprintf(
                'Candidate precision %.1f%% is below the %.1f%% deployment gate.',
                $metrics['precision'] * 100,
                $this->minimumDeployPrecision() * 100,
            );
        }

        return $reasons === [] ? null : implode(' ', $reasons);
    }

    /**
     * Absolute path to the persisted model file.
     */
    public function modelPath(): string
    {
        return storage_path('app/'.config('sast.training.model_path', self::MODEL_PATH));
    }

    /** Return the absolute path of the currently certified model, if any. */
    public function activeModelPath(): ?string
    {
        $runtime = $this->modelRuntime();

        return ($runtime['certified'] ?? false) ? $runtime['path'] : null;
    }

    private function minimumTrainingSamples(): int
    {
        return max(2, (int) config('sast.training.min_training_samples', 50));
    }

    private function tpFlagThreshold(): float
    {
        return min(1.0, max(0.0, (float) config('sast.training.tp_flag_threshold', 0.8)));
    }

    private function fpFlagThreshold(): float
    {
        return min(1.0, max(0.0, (float) config('sast.training.fp_flag_threshold', 0.15)));
    }

    private function minimumDeployPrecision(): float
    {
        return min(1.0, max(0.0, (float) config('sast.training.min_deploy_precision', 0.8)));
    }

    private function minimumDeployFlags(): int
    {
        return max(1, (int) config('sast.training.min_deploy_flags', 5));
    }

    private function candidateModelPath(string $datasetFingerprint): string
    {
        $base = str_replace('\\', '/', (string) config('sast.training.model_path', self::MODEL_PATH));
        $directory = dirname($base);
        $prefix = $directory === '.' ? '' : trim($directory, '/').'/';
        $name = pathinfo($base, PATHINFO_FILENAME);

        return sprintf(
            '%smodels/%s_%s_%s.rbx',
            $prefix,
            $name,
            substr($datasetFingerprint, 0, 12),
            Str::uuid(),
        );
    }

    private function absoluteStoragePath(string $relativePath): string
    {
        return storage_path('app/'.ltrim(str_replace('\\', '/', $relativePath), '/'));
    }

    /**
     * @return array{path:string,certified:bool,tp_threshold:float,fp_threshold:float,feature_order:list<string>}|null
     */
    private function modelRuntime(): ?array
    {
        $activeStates = ModelState::query()
            ->where('deployment_status', 'deployed')
            ->whereNotNull('model_path')
            ->latest('trained_at')
            ->latest('id')
            ->get(['id', 'model_path', 'decision_threshold', 'evaluation_metadata']);

        foreach ($activeStates as $state) {
            $path = $this->absoluteStoragePath((string) $state->model_path);

            if (is_file($path)) {
                $declaredOrder = $state->evaluation_metadata['feature_order'] ?? null;
                $featureOrder = $this->validFeatureOrder($declaredOrder)
                    ? array_values($declaredOrder)
                    : self::LEGACY_FEATURE_ORDER;

                return [
                    'path' => $path,
                    'certified' => true,
                    'tp_threshold' => (float) ($state->decision_threshold ?? $this->tpFlagThreshold()),
                    'fp_threshold' => $this->fpFlagThreshold(),
                    'feature_order' => $featureOrder,
                ];
            }
        }

        $advisoryStates = ModelState::query()
            ->where('deployment_status', 'legacy')
            ->whereNotNull('model_path')
            ->latest('trained_at')
            ->latest('id')
            ->get(['id', 'model_path', 'decision_threshold', 'evaluation_metadata']);

        foreach ($advisoryStates as $state) {
            $path = $this->absoluteStoragePath((string) $state->model_path);

            if (! is_file($path)) {
                continue;
            }

            $declaredOrder = $state->evaluation_metadata['feature_order'] ?? null;
            $featureOrder = $this->validFeatureOrder($declaredOrder)
                ? array_values($declaredOrder)
                : self::LEGACY_FEATURE_ORDER;

            return [
                'path' => $path,
                'certified' => false,
                'tp_threshold' => (float) ($state->decision_threshold ?? $this->tpFlagThreshold()),
                'fp_threshold' => $this->fpFlagThreshold(),
                'feature_order' => $featureOrder,
            ];
        }

        $legacyPath = $this->modelPath();

        if (is_file($legacyPath)) {
            return [
                'path' => $legacyPath,
                'certified' => false,
                'tp_threshold' => $this->tpFlagThreshold(),
                'fp_threshold' => $this->fpFlagThreshold(),
                'feature_order' => self::LEGACY_FEATURE_ORDER,
            ];
        }

        return null;
    }

    private function validFeatureOrder(mixed $order): bool
    {
        return is_array($order)
            && $order !== []
            && array_is_list($order)
            && count(array_filter($order, 'is_string')) === count($order);
    }

    private function loadModel(string $path): PersistentModel
    {
        if ($this->model !== null && $this->loadedModelPath === $path) {
            return $this->model;
        }

        if (! file_exists($path)) {
            throw new \RuntimeException(
                'No trained model found at '.$path.'. Run the training job first (php artisan sast:train).'
            );
        }

        $this->model = PersistentModel::load(new Filesystem($path));
        $this->loadedModelPath = $path;

        return $this->model;
    }
}
