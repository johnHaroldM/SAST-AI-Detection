<?php

use App\Http\Controllers\ScanIngestController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Machine Ingestion
|--------------------------------------------------------------------------
|
| Loaded stateless and rate limited — see the `then` closure in
| bootstrap/app.php. Authentication is a per-project ingest token presented
| as a bearer credential, which grants exactly one capability: upload a scan
| report for that project. It cannot read anything back.
|
*/

Route::post('/ingest/scans', [ScanIngestController::class, 'store'])->name('ingest.scans.store');
