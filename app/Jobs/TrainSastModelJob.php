<?php

namespace App\Jobs;

use App\Exceptions\InsufficientTrainingDataException;
use App\Models\Finding;
use App\Models\ModelState;
use App\Services\RubixTriageService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
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
class TrainSastModelJob implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 1; // don't silently retry a failed training run

    public int $timeout = 1800;

    /** Prevent duplicate clicks/commands from queueing the same expensive fit. */
    public int $uniqueFor = 3600;

    /** Nullable so queue payloads serialized before this flag existed remain valid. */
    public ?bool $force = null;

    public function __construct(bool $force = false)
    {
        $this->force = $force;
    }

    public function uniqueId(): string
    {
        return 'rubix-sast-training';
    }

    public function handle(RubixTriageService $triageService): void
    {
        $forced = $this->force ?? false;

        if (! $forced && ! $this->hasNewLabels()) {
            cache()->forget('sast:retrain-lock');
            Log::info('SAST model retraining skipped because no labels changed.');

            return;
        }

        Log::info('SAST model retraining started.');

        try {
            $metrics = $triageService->train();

            if ($metrics['deployment_status'] === 'deployed') {
                Log::info('SAST model candidate passed validation and was deployed.', $metrics);
            } else {
                Log::warning('SAST model candidate was rejected; active model unchanged.', $metrics);
            }
        } catch (InsufficientTrainingDataException $e) {
            // Expected during cold start — not a failure worth alerting on.
            Log::info('SAST model retraining skipped.', ['reason' => $e->getMessage()]);
        } finally {
            cache()->forget('sast:retrain-lock');
        }
    }

    public function failed(\Throwable $e): void
    {
        cache()->forget('sast:retrain-lock');
        Log::error('SAST model retraining failed.', ['error' => $e->getMessage()]);
    }

    private function hasNewLabels(): bool
    {
        $lastTrainedAt = ModelState::max('trained_at');

        if ($lastTrainedAt === null) {
            return true;
        }

        return Finding::query()
            ->whereNotNull('final_label')
            ->whereNotNull('feature_vector')
            ->where('updated_at', '>', $lastTrainedAt)
            ->exists();
    }
}
