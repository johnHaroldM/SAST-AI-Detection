<?php

use App\Http\Controllers\Web\FindingReportController;
use App\Http\Controllers\Web\ModelDashboardController;
use App\Http\Controllers\Web\ProjectDashboardController;
use App\Http\Controllers\Web\RuleDashboardController;
use App\Http\Controllers\Web\ScanDashboardController;
use App\Http\Controllers\Web\TriageQueueController;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

Route::get('/', fn () => Inertia::render('welcome'))->name('home');

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/dashboard', [ScanDashboardController::class, 'index'])->name('dashboard');

    Route::get('/scans', [ScanDashboardController::class, 'index'])->name('scans.index');
    Route::get('/scans/upload', [ScanDashboardController::class, 'create'])->name('scans.create');
    Route::post('/scans', [ScanDashboardController::class, 'store'])->name('scans.store');
    Route::get('/scans/{scan}', [ScanDashboardController::class, 'show'])->name('scans.show');
    Route::post('/scans/{scan}/anino-analysis', [ScanDashboardController::class, 'analyzeWithAnino'])->name('scans.anino.analyze');
    Route::post('/scans/{scan}/anino-training', [ScanDashboardController::class, 'trainFromAnino'])->name('scans.anino.train');

    Route::get('/projects', [ProjectDashboardController::class, 'index'])->name('projects.index');
    Route::post('/projects', [ProjectDashboardController::class, 'store'])->name('projects.store');
    Route::patch('/projects/{project}', [ProjectDashboardController::class, 'update'])->name('projects.update');
    Route::post('/projects/{project}/scan', [ProjectDashboardController::class, 'scan'])->name('projects.scan');
    Route::post('/projects/{project}/token', [ProjectDashboardController::class, 'issueToken'])->name('projects.token.issue');
    Route::delete('/projects/{project}/token', [ProjectDashboardController::class, 'revokeToken'])->name('projects.token.revoke');

    Route::get('/triage', [TriageQueueController::class, 'index'])->name('triage.queue');
    Route::get('/findings/{finding}', [FindingReportController::class, 'show'])->name('findings.report');

    Route::get('/rules/noisy', [RuleDashboardController::class, 'noisy'])->name('rules.noisy');

    Route::get('/model', [ModelDashboardController::class, 'index'])->name('model.index');
    Route::post('/model/train', [ModelDashboardController::class, 'train'])->name('model.train');
});

require __DIR__.'/settings.php';
