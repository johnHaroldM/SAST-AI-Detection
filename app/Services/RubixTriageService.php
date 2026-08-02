<?php

namespace App\Services;

use App\Exceptions\InsufficientTrainingDataException;
use App\Models\Finding;
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
 */
class RubixTriageService
{
    private const MODEL_PATH = 'sast_triage_model.rbx';

    // Order matters: must match the order features are appended to each sample row.
    private const FEATURE_ORDER = [
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

    private ?PersistentModel $model = null;

    /**
     * Build the raw ordered feature row Rubix expects from a finding's
     * associative feature vector (as produced by AstFeatureExtractor
     * + rule history + scanner metadata).
     *
     * @param  array<string, mixed>  $featureVector
     * @return list<mixed>
     */
    public function vectorize(array $featureVector): array
    {
        return array_map(
            fn (string $key) => $featureVector[$key] ?? $this->defaultFor($key),
            self::FEATURE_ORDER
        );
    }

    private function defaultFor(string $key): string|int|float|null
    {
        return match ($key) {
            'cwe_id', 'cyclomatic_complexity', 'line_depth_in_function' => 0,
            'is_test_file', 'has_sanitizer_in_ast' => 0,
            'historical_fp_rate_rule' => 0.0,
            'scanner_severity' => 'MEDIUM',
            'file_extension' => 'php',
            'developer_experience_lvl' => 'unknown',
            default => null,
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
        return file_exists($this->modelPath());
    }

    /**
     * Predict True Positive probability for a single Finding.
     * Persists the score and predicted_label back onto the model.
     */
    public function predictFinding(Finding $finding): Finding
    {
        $probabilities = $this->probabilitiesFor([$this->vectorize($finding->feature_vector ?? [])])[0] ?? [];

        $this->applyPrediction($finding, $probabilities);
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

        if (! $this->hasTrainedModel()) {
            // Cold start: no model yet. Leave predicted_label/tp_probability
            // null so the triage UI shows these as unscored rather than
            // presenting a fabricated confidence, and so the ingestion
            // pipeline still completes and produces labelable rows.
            return 0;
        }

        $samples = array_values(array_map(
            fn (Finding $f) => $this->vectorize($f->feature_vector ?? []),
            $findingsArray
        ));
        $probabilities = $this->probabilitiesFor($samples);

        foreach (array_values($findingsArray) as $i => $finding) {
            $this->applyPrediction($finding, $probabilities[$i] ?? []);
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
     * The predicted label is the argmax of these probabilities, which is
     * exactly what RandomForest::predict() would have returned anyway.
     *
     * @param  list<list<mixed>>  $samples
     * @return list<array<string, float>>
     */
    private function probabilitiesFor(array $samples): array
    {
        return $this->loadModel()->proba(new Unlabeled($samples));
    }

    /**
     * @param  array<string, float>  $probabilities
     */
    private function applyPrediction(Finding $finding, array $probabilities): void
    {
        $tpProbability = (float) ($probabilities['true_positive'] ?? 0.0);
        $fpProbability = (float) ($probabilities['false_positive'] ?? 0.0);

        $finding->predicted_label = $tpProbability >= $fpProbability ? 'true_positive' : 'false_positive';
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
        $counts = Finding::query()
            ->whereNotNull('final_label')
            ->whereNotNull('feature_vector')
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
     * Train (or retrain) the model from all confirmed triage feedback
     * (findings with a non-null final_label). Called from
     * TrainSastModelJob, never synchronously from a web request.
     *
     * @return array{sample_size:int, precision:float, recall:float, f1_score:float, confusion:array<string,int>, trained_on:int}
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

        $findings = Finding::query()
            ->whereNotNull('final_label')
            ->whereNotNull('feature_vector')
            ->get();

        $samples = [];
        $labels = [];

        foreach ($findings as $finding) {
            $samples[] = $this->vectorize($finding->feature_vector);
            $labels[] = $finding->final_label; // 'true_positive' | 'false_positive'
        }

        $dataset = new Labeled($samples, $labels);
        [$training, $testing] = $dataset->stratifiedSplit(
            (float) config('sast.training.test_split_ratio', 0.8)
        );

        $estimator = new Pipeline([
            new OneHotEncoder,
            new ZScaleStandardizer,
        ], new RandomForest(
            new ClassificationTree((int) config('sast.forest.max_tree_depth', 10)),
            (int) config('sast.forest.estimators', 100),
            (float) config('sast.forest.bagging_ratio', 0.5),
            (bool) config('sast.forest.balanced', true),
        ));

        $estimator->train($training);

        $predictions = array_values(array_map(strval(...), $estimator->predict($testing)));
        $actual = array_values(array_map(strval(...), $testing->labels()));

        $metrics = $this->scoreModel($predictions, $actual);
        $metrics['trained_on'] = $training->numSamples();

        $path = $this->modelPath();

        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0755, true);
        }

        $persistentModel = new PersistentModel($estimator, new Filesystem($path));
        $persistentModel->save();

        $this->model = null; // force reload of the freshly trained model on next use

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

    /**
     * Absolute path to the persisted model file.
     */
    public function modelPath(): string
    {
        return storage_path('app/'.config('sast.training.model_path', self::MODEL_PATH));
    }

    private function minimumTrainingSamples(): int
    {
        return max(2, (int) config('sast.training.min_training_samples', 50));
    }

    private function loadModel(): PersistentModel
    {
        if ($this->model !== null) {
            return $this->model;
        }

        $path = $this->modelPath();

        if (! file_exists($path)) {
            throw new \RuntimeException(
                'No trained model found at '.$path.'. Run the training job first (php artisan sast:train).'
            );
        }

        $this->model = PersistentModel::load(new Filesystem($path));

        return $this->model;
    }
}
