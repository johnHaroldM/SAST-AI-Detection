<?php

namespace App\Jobs;

use App\Models\ModelState;
use App\Services\RubixTriageService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

/**
 * Retrains the Random Forest classifier from all confirmed triage
 * feedback and persists it via Rubix's PersistentModel/Filesystem
 * persister. Dispatched either manually (php artisan sast:train),
 * on a schedule, or automatically once a batch of new labels has
 * accumulated (see TriageController::maybeTriggerRetraining).
 */
class TrainSastModelJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 1; // don't silently retry a failed training run
    public int $timeout = 1800;

    public function handle(RubixTriageService $triageService): void
    {
        Log::info('SAST model retraining started.');

        try {
            $metrics = $triageService->train();

            ModelState::create([
                'trained_at' => now(),
                'sample_size' => $metrics['sample_size'],
                'precision' => $metrics['precision'],
                'recall' => $metrics['recall'],
                'f1_score' => $metrics['f1_score'],
                'confusion_matrix' => $metrics['confusion'],
            ]);

            Log::info('SAST model retraining complete.', $metrics);
        } finally {
            cache()->forget('sast:retrain-lock');
        }
    }

    public function failed(\Throwable $e): void
    {
        cache()->forget('sast:retrain-lock');
        Log::error('SAST model retraining failed.', ['error' => $e->getMessage()]);
    }
}
