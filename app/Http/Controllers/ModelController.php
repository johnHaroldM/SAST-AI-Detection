<?php

namespace App\Http\Controllers;

use App\Jobs\TrainSastModelJob;
use App\Models\ModelState;
use App\Services\RubixTriageService;
use Illuminate\Http\JsonResponse;

/**
 * Exposes the training loop to the UI: how close the label set is to being
 * trainable, how the last run scored, and a trigger to kick off a new run.
 *
 * Training itself is always dispatched to the queue — a full RandomForest
 * fit over the label set is far too slow to hold an HTTP request open.
 */
class ModelController extends Controller
{
    public function __construct(private RubixTriageService $triageService) {}

    /**
     * GET /api/model/status
     */
    public function status(): JsonResponse
    {
        return response()->json($this->buildStatus());
    }

    /**
     * POST /api/model/train
     *
     * Returns 422 when the label set can't support a training run yet, so
     * the caller gets the specific shortfall rather than a queued job that
     * fails a few seconds later out of sight.
     */
    public function train(): JsonResponse
    {
        $readiness = $this->triageService->trainingReadiness();

        if (! $readiness['ready']) {
            return response()->json([
                'message' => $this->shortfallMessage($readiness),
                'readiness' => $readiness,
            ], 422);
        }

        if (! cache()->add('sast:retrain-lock', true, now()->addMinutes(30))) {
            return response()->json([
                'message' => 'A training run is already in progress.',
                'readiness' => $readiness,
            ], 409);
        }

        TrainSastModelJob::dispatch(force: true)->onQueue('ml-training');

        return response()->json([
            'message' => 'Training run queued.',
            'readiness' => $readiness,
        ], 202);
    }

    /**
     * Shared by the JSON endpoint and the Inertia dashboard.
     *
     * @return array<string, mixed>
     */
    public function buildStatus(): array
    {
        $history = ModelState::query()->latest('trained_at')->limit(20)->get();
        $active = ModelState::query()
            ->where('deployment_status', 'deployed')
            ->latest('trained_at')
            ->first();

        return [
            'readiness' => $this->triageService->trainingReadiness(),
            'has_trained_model' => $this->triageService->hasTrainedModel(),
            'has_certified_model' => $this->triageService->hasCertifiedModel(),
            'active' => $active,
            'latest' => $history->first(),
            'history' => $history->reverse()->values(),
            'training_in_progress' => cache()->has('sast:retrain-lock'),
        ];
    }

    /**
     * @param  array{total:int, true_positive:int, false_positive:int, required:int, ready:bool}  $readiness
     */
    private function shortfallMessage(array $readiness): string
    {
        if ($readiness['total'] < $readiness['required']) {
            return sprintf(
                'Need %d more triaged findings before training (%d of %d).',
                $readiness['required'] - $readiness['total'],
                $readiness['total'],
                $readiness['required'],
            );
        }

        return $readiness['true_positive'] === 0
            ? 'Training needs at least one finding confirmed as a true positive.'
            : 'Training needs at least one finding marked as a false positive.';
    }
}
