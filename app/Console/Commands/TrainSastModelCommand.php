<?php

namespace App\Console\Commands;

use App\Jobs\TrainSastModelJob;
use App\Services\RubixTriageService;
use Illuminate\Console\Command;

class TrainSastModelCommand extends Command
{
    protected $signature = 'sast:train {--sync : Run training synchronously instead of queuing it}';
    protected $description = 'Train (or retrain) the Rubix ML false-positive classifier from confirmed triage feedback';

    public function handle(RubixTriageService $triageService): int
    {
        if (!$this->option('sync')) {
            TrainSastModelJob::dispatch()->onQueue('ml-training');
            $this->info('Training job queued on [ml-training]. Monitor via Horizon or `php artisan queue:work`.');
            return self::SUCCESS;
        }

        $this->info('Training synchronously — this may take a while for large label sets...');

        try {
            $metrics = $triageService->train();
        } catch (\RuntimeException $e) {
            $this->error($e->getMessage());
            return self::FAILURE;
        }

        $this->table(
            ['Metric', 'Value'],
            [
                ['Sample size', $metrics['sample_size']],
                ['Precision', $metrics['precision']],
                ['Recall', $metrics['recall']],
                ['F1 Score', $metrics['f1_score']],
                ['Confusion (TP/FP/FN/TN)', implode(' / ', $metrics['confusion'])],
            ]
        );

        return self::SUCCESS;
    }
}
