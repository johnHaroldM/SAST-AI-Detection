<?php

namespace App\Services;

use App\Jobs\ProcessScanJob;
use App\Models\Scan;
use Illuminate\Http\UploadedFile;

/**
 * Stores an uploaded scanner report and queues the ingestion pipeline.
 *
 * Extracted so the JSON API and the Inertia upload form share one code
 * path — they differ only in how they respond, not in what they do.
 */
class ScanIngestionService
{
    /**
     * @param  array<string, mixed>  $attributes  Validated payload from StoreScanRequest.
     */
    public function ingest(array $attributes, UploadedFile $report): Scan
    {
        $storedPath = $report->store('sast-reports/'.$attributes['project_id']);

        $scan = Scan::create([
            'project_id' => $attributes['project_id'],
            'source' => $attributes['source'],
            'commit_sha' => strtolower((string) $attributes['commit_sha']),
            'branch' => $attributes['branch'],
            'raw_report_path' => $storedPath,
            'status' => 'uploaded',
        ]);

        ProcessScanJob::dispatch($scan);

        return $scan;
    }
}
