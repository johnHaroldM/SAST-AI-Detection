<?php

use App\Http\Controllers\Web\RuleDashboardController;
use App\Http\Controllers\Web\ScanDashboardController;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth', 'verified'])->group(function () {
    Route::redirect('/', '/scans');

    Route::get('/scans', [ScanDashboardController::class, 'index'])->name('scans.index');
    Route::get('/scans/upload', [ScanDashboardController::class, 'create'])->name('scans.create');
    Route::get('/scans/{scan}', [ScanDashboardController::class, 'show'])->name('scans.show');

    Route::get('/rules/noisy', [RuleDashboardController::class, 'noisy'])->name('rules.noisy');
});
