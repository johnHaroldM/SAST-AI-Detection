<?php

namespace App\Jobs;

use App\Models\Finding;
use App\Models\Scan;
use App\Services\FeatureVectorBuilder;
use App\Services\RubixTriageService;
use App\Services\ScannerReportParsers\ReportParserFactory;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

/**
 * The full ingestion pipeline from the architecture doc's workflow diagram,
 * steps 2-5:
 *   Directory & AST Enrichment -> Feature Vector Extraction -> Rubix ML Engine -> Storage
 *
 * Runs on the default queue; heavy enough (AST parsing per finding, git
 * blame shellouts) that it must never run inline on an HTTP request.
 */
class ProcessScanJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 3;
    public int $timeout = 900; // large monorepo scans can take a while

    public function __construct(public Scan $scan) {}

    public function handle(
        ReportParserFactory $parserFactory,
        FeatureVectorBuilder $vectorBuilder,
        RubixTriageService $triageService,
    ): void {
        $this->scan->update(['status' => 'parsing']);

        try {
            $reportContents = Storage::get($this->scan->raw_report_path);
            $parser = $parserFactory->make($this->scan->source);
            $parsedFindings = $parser->parse($reportContents); // normalized DTOs

            $findings = collect($parsedFindings)->map(function ($dto) {
                return Finding::create([
                    'scan_id'     => $this->scan->id,
                    'rule_id'     => $dto->ruleId,
                    'cwe_id'      => $dto->cweId,
                    'file_path'   => $dto->filePath,
                    'line_number' => $dto->lineNumber,
                    'severity'    => $dto->severity,
                    'message'     => $dto->message,
                    'raw_snippet' => $dto->snippet,
                    'status'      => 'pending',
                ]);
            });

            $this->scan->update([
                'status' => 'scoring',
                'total_findings' => $findings->count(),
            ]);

            $projectRoot = $this->resolveCheckedOutPath($this->scan);

            // Steps: AST enrichment -> feature vector assembly, in batch to
            // avoid N+1 Rule lookups.
            $vectorBuilder->buildBatch($findings, $projectRoot);

            // Rubix ML batch inference — one model load, one predict() call
            // over the entire dataset rather than per-finding overhead.
            $triageService->predictBatch($findings->fresh());

            $suppressedCount = $findings->fresh()
                ->filter(fn (Finding $f) => $f->predicted_label === 'false_positive' && $f->tp_probability <= 0.15)
                ->count();

            $this->scan->update([
                'status' => 'complete',
                'suppressed_count' => $suppressedCount,
            ]);

            // Auto PR-comment step is intentionally a separate queued job
            // (PostPrCommentsJob) triggered from here so a VCS API outage
            // doesn't fail or retry the whole ingestion pipeline.
            PostPrCommentsJob::dispatch($this->scan)->onQueue('vcs-integrations');

        } catch (\Throwable $e) {
            $this->scan->update(['status' => 'failed']);
            Log::error('SAST scan processing failed', [
                'scan_id' => $this->scan->id,
                'error' => $e->getMessage(),
            ]);
            throw $e;
        }
    }

    private function resolveCheckedOutPath(Scan $scan): string
    {
        // In production this triggers a shallow git clone/checkout of
        // $scan->commit_sha into a scoped workspace dir if not already
        // cached locally. Abstracted here for brevity.
        return storage_path("app/workspaces/{$scan->project_id}/{$scan->commit_sha}");
    }
}
