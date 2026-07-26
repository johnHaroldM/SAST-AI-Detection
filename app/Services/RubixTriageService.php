<?php

namespace App\Services;

use App\Models\Finding;
use App\Models\Rule;
use Rubix\ML\Classifiers\ClassificationTree;
use Rubix\ML\Classifiers\RandomForest;
use Rubix\ML\Datasets\Labeled;
use Rubix\ML\Datasets\Unlabeled;
use Rubix\ML\Persisters\Filesystem;
use Rubix\ML\PersistentModel;
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
     */
    public function vectorize(array $featureVector): array
    {
        return array_map(
            fn (string $key) => $featureVector[$key] ?? $this->defaultFor($key),
            self::FEATURE_ORDER
        );
    }

    private function defaultFor(string $key)
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
     * Predict True Positive probability for a single Finding.
     * Persists the score and predicted_label back onto the model.
     */
    public function predictFinding(Finding $finding): Finding
    {
        $model = $this->loadModel();

        $sample = $this->vectorize($finding->feature_vector);
        $dataset = new Unlabeled([$sample]);

        $prediction = $model->predict($dataset)[0];       // 'true_positive' | 'false_positive'
        $probabilities = $model->predictProbabilities($dataset)[0] ?? [];
        $tpProbability = $probabilities['true_positive'] ?? ($prediction === 'true_positive' ? 1.0 : 0.0);

        $finding->predicted_label = $prediction;
        $finding->tp_probability = round($tpProbability, 4);
        $finding->status = 'pending'; // awaiting human triage or auto-suppression rule
        $finding->save();

        return $finding;
    }

    /**
     * Batch prediction, used by the ingestion pipeline after a full scan
     * has been parsed and feature-vectorized. Far more efficient than
     * calling predictFinding() in a loop because the model is loaded once
     * and Rubix predicts over the whole dataset in a single pass.
     */
    public function predictBatch(iterable $findings): void
    {
        $model = $this->loadModel();
        $findingsArray = is_array($findings) ? $findings : iterator_to_array($findings);

        if (empty($findingsArray)) {
            return;
        }

        $samples = array_map(fn (Finding $f) => $this->vectorize($f->feature_vector), $findingsArray);
        $dataset = new Unlabeled($samples);

        $predictions = $model->predict($dataset);
        $probabilities = $model->predictProbabilities($dataset);

        foreach ($findingsArray as $i => $finding) {
            $tp = $probabilities[$i]['true_positive'] ?? ($predictions[$i] === 'true_positive' ? 1.0 : 0.0);
            $finding->predicted_label = $predictions[$i];
            $finding->tp_probability = round($tp, 4);
            $finding->status = 'pending';
            $finding->save();
        }
    }

    /**
     * Train (or retrain) the model from all confirmed triage feedback
     * (findings with a non-null final_label). Called from
     * TrainSastModelJob, never synchronously from a web request.
     */
    public function train(): array
    {
        $findings = Finding::query()
            ->whereNotNull('final_label')
            ->whereNotNull('feature_vector')
            ->get();

        if ($findings->count() < 50) {
            throw new \RuntimeException(
                "Insufficient labeled data to train: {$findings->count()} rows (minimum 50)."
            );
        }

        $samples = [];
        $labels = [];

        foreach ($findings as $finding) {
            $samples[] = $this->vectorize($finding->feature_vector);
            $labels[] = $finding->final_label; // 'true_positive' | 'false_positive'
        }

        $dataset = new Labeled($samples, $labels);
        [$training, $testing] = $dataset->stratifiedSplit(0.8);

        $estimator = new Pipeline([
            new OneHotEncoder(),
            new ZScaleStandardizer(),
        ], new RandomForest(
            new ClassificationTree(10), // max tree depth
            100,                        // number of trees in the forest
            0.5,                        // ratio of training set sampled per tree (bagging)
        ));

        $estimator->train($training);

        $predictions = $estimator->predict($testing);
        $metrics = $this->scoreModel($predictions, $testing->labels());

        $persistentModel = new PersistentModel(
            $estimator,
            new Filesystem(storage_path('app/' . self::MODEL_PATH))
        );
        $persistentModel->save();

        $this->model = null; // force reload of the freshly trained model on next use

        return $metrics;
    }

    /**
     * Compute precision/recall/F1 for the 'true_positive' class on the
     * held-out test split. Kept dependency-free (no rubix Reports needed)
     * so it's easy to log/store in model_states.
     */
    private function scoreModel(array $predictions, array $actual): array
    {
        $tp = $fp = $fn = $tn = 0;

        foreach ($predictions as $i => $predicted) {
            $truth = $actual[$i];
            if ($predicted === 'true_positive' && $truth === 'true_positive') $tp++;
            elseif ($predicted === 'true_positive' && $truth === 'false_positive') $fp++;
            elseif ($predicted === 'false_positive' && $truth === 'true_positive') $fn++;
            else $tn++;
        }

        $precision = ($tp + $fp) > 0 ? $tp / ($tp + $fp) : 0.0;
        $recall = ($tp + $fn) > 0 ? $tp / ($tp + $fn) : 0.0;
        $f1 = ($precision + $recall) > 0 ? 2 * ($precision * $recall) / ($precision + $recall) : 0.0;

        return [
            'sample_size' => count($predictions),
            'precision'   => round($precision, 4),
            'recall'      => round($recall, 4),
            'f1_score'    => round($f1, 4),
            'confusion'   => compact('tp', 'fp', 'fn', 'tn'),
        ];
    }

    private function loadModel(): PersistentModel
    {
        if ($this->model !== null) {
            return $this->model;
        }

        $path = storage_path('app/' . self::MODEL_PATH);

        if (!file_exists($path)) {
            throw new \RuntimeException(
                'No trained model found at ' . $path . '. Run the training job first (php artisan sast:train).'
            );
        }

        $this->model = PersistentModel::load(new Filesystem($path));

        return $this->model;
    }
}
