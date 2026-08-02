<?php

namespace App\Console\Commands;

use App\Exceptions\InsufficientTrainingDataException;
use App\Jobs\TrainSastModelJob;
use App\Models\ModelState;
use App\Services\RubixTriageService;
use Illuminate\Console\Command;

class TrainSastModelCommand extends Command
{
    protected $signature = 'sast:train {--sync : Run training synchronously instead of queuing it}';

    protected $description = 'Train (or retrain) the Rubix ML false-positive classifier from confirmed triage feedback';

    public function handle(RubixTriageService $triageService): int
    {
        $readiness = $triageService->trainingReadiness();

        $this->line(sprintf(
            'Labeled findings: <options=bold>%d</> of %d required (%d true positive / %d false positive)',
            $readiness['total'],
            $readiness['required'],
            $readiness['true_positive'],
            $readiness['false_positive'],
        ));

        if (! $readiness['ready']) {
            $this->error('Not enough labeled data to train yet.');
            $this->line('Triage findings in the dashboard, or via POST /api/findings/{id}/triage, then run this again.');

            return self::FAILURE;
        }

        if (! $this->option('sync')) {
            TrainSastModelJob::dispatch()->onQueue('ml-training');
            $this->info('Training job queued on [ml-training]. Run `php artisan queue:work --queue=ml-training` to process it.');

            return self::SUCCESS;
        }

        $this->info('Training synchronously — this may take a while for large label sets...');

        try {
            $metrics = $triageService->train();
        } catch (InsufficientTrainingDataException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        ModelState::create([
            'trained_at' => now(),
            'sample_size' => $metrics['sample_size'],
            'precision' => $metrics['precision'],
            'recall' => $metrics['recall'],
            'f1_score' => $metrics['f1_score'],
            'confusion_matrix' => $metrics['confusion'],
        ]);

        $this->newLine();
        $this->table(
            ['Metric', 'Value'],
            [
                ['Trained on', $metrics['trained_on'].' samples'],
                ['Held-out test size', $metrics['sample_size']],
                ['Precision', $metrics['precision']],
                ['Recall', $metrics['recall']],
                ['F1 Score', $metrics['f1_score']],
                ['Confusion (TP/FP/FN/TN)', implode(' / ', $metrics['confusion'])],
            ]
        );

        $this->info('Model saved to '.$triageService->modelPath());

        return self::SUCCESS;
    }
}
