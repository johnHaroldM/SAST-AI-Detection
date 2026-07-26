<?php

use App\Http\Controllers\RuleController;
use App\Http\Controllers\ScanController;
use App\Http\Controllers\TriageController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->group(function () {

    // Ingestion
    Route::post('/scans', [ScanController::class, 'store']);
    Route::get('/scans/{scan}', [ScanController::class, 'show']);
    Route::get('/scans/{scan}/findings', [ScanController::class, 'findings']);

    // Human-in-the-loop triage (feeds the retraining loop)
    Route::post('/findings/{finding}/triage', [TriageController::class, 'store']);
    Route::post('/findings/bulk-triage', [TriageController::class, 'bulkStore']);

    // Rule noise / recommendation engine
    Route::get('/rules/noisy', [RuleController::class, 'noisy']);
    Route::get('/rules/{rule}/stats', [RuleController::class, 'show']);
});
