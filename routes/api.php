<?php

use App\Http\Controllers\AiAssessmentFeedbackController;
use App\Http\Controllers\ModelController;
use App\Http\Controllers\RuleController;
use App\Http\Controllers\ScanController;
use App\Http\Controllers\TriageController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| SAST JSON Endpoints
|--------------------------------------------------------------------------
|
| Loaded under the `web` middleware group with an /api prefix — see the
| `then` closure in bootstrap/app.php. Session-authenticated and
| CSRF-protected, because the only consumer is this app's Inertia SPA.
|
*/

Route::middleware(['auth', 'verified'])->group(function () {

    // Ingestion
    Route::post('/scans', [ScanController::class, 'store'])->name('api.scans.store');
    Route::get('/scans/{scan}', [ScanController::class, 'show'])->name('api.scans.show');
    Route::get('/scans/{scan}/findings', [ScanController::class, 'findings'])->name('api.scans.findings');
    Route::get('/scans/{scan}/anino-status', [ScanController::class, 'aninoStatus'])->name('api.scans.anino-status');

    // Human-in-the-loop triage (feeds the retraining loop)
    Route::post('/findings/{finding}/triage', [TriageController::class, 'store'])->name('api.findings.triage');
    Route::delete('/findings/{finding}/triage', [TriageController::class, 'destroy'])->name('api.findings.untriage');
    Route::post('/findings/bulk-triage', [TriageController::class, 'bulkStore'])->name('api.findings.bulk-triage');

    // Explicit human review of ATAKE / DEPENSA output (does not set ground truth)
    Route::put('/ai-assessments/{aiAssessment}/feedback', [AiAssessmentFeedbackController::class, 'update'])
        ->name('api.ai-assessments.feedback.update');
    Route::delete('/ai-assessments/{aiAssessment}/feedback', [AiAssessmentFeedbackController::class, 'destroy'])
        ->name('api.ai-assessments.feedback.destroy');

    // Model training + status
    Route::get('/model/status', [ModelController::class, 'status'])->name('api.model.status');
    Route::post('/model/train', [ModelController::class, 'train'])->name('api.model.train');

    // Rule noise / recommendation engine
    Route::get('/rules/noisy', [RuleController::class, 'noisy'])->name('api.rules.noisy');
    Route::get('/rules/{rule}/stats', [RuleController::class, 'show'])->name('api.rules.stats');
});
