<?php

namespace App\Http\Controllers\Web;

use App\Http\Controllers\Controller;
use App\Http\Controllers\ModelController;
use App\Jobs\TrainSastModelJob;
use App\Services\RubixTriageService;
use Illuminate\Http\RedirectResponse;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The in-app training screen: shows how many labels have accumulated, what
 * the last training run scored, and lets a security engineer kick off a
 * retrain without dropping to the CLI.
 *
 * Reuses ModelController::buildStatus() rather than duplicating the
 * readiness/history queries, same pattern as ScanDashboardController.
 */
class ModelDashboardController extends Controller
{
    public function __construct(
        private ModelController $modelController,
        private RubixTriageService $triageService,
    ) {}

    public function index(): Response
    {
        return Inertia::render('Model/Index', $this->modelController->buildStatus());
    }

    public function train(): RedirectResponse
    {
        $readiness = $this->triageService->trainingReadiness();

        if (! $readiness['ready']) {
            return back()->with('error', sprintf(
                'Not enough labeled data yet — %d of %d triaged findings, %d true positive / %d false positive.',
                $readiness['total'],
                $readiness['required'],
                $readiness['true_positive'],
                $readiness['false_positive'],
            ));
        }

        if (! cache()->add('sast:retrain-lock', true, now()->addMinutes(30))) {
            return back()->with('error', 'A training run is already in progress.');
        }

        TrainSastModelJob::dispatch()->onQueue('ml-training');

        return back()->with('success', sprintf(
            'Training run queued on %d labeled findings. Metrics appear here when it completes.',
            $readiness['total'],
        ));
    }
}
