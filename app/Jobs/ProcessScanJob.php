<?php

namespace App\Jobs;

use App\Models\AninoAnalysisRun;
use App\Models\Finding;
use App\Models\Scan;
use App\Services\AI\AninoCandidateSelector;
use App\Services\AI\FindingContextBuilder;
use App\Services\FeatureVectorBuilder;
use App\Services\RubixTriageService;
use App\Services\ScannerReportParsers\ReportParserFactory;
use App\Services\Workspaces\SourceWorkspaceFactory;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
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
        SourceWorkspaceFactory $workspaces,
        FindingContextBuilder $aiContextBuilder,
    ): void {
        $this->scan->update(['status' => 'parsing']);

        $workspace = null;

        try {
            $reportContents = Storage::get($this->scan->raw_report_path);
            $parser = $parserFactory->make($this->scan->source);
            $parsedFindings = $parser->parse($reportContents); // normalized DTOs

            $findings = new EloquentCollection(array_map(function ($dto) {
                return Finding::create([
                    'scan_id' => $this->scan->id,
                    'rule_id' => $dto->ruleId,
                    'cwe_id' => $dto->cweId,
                    'file_path' => $dto->filePath,
                    'line_number' => $dto->lineNumber,
                    'severity' => $dto->severity,
                    'message' => $dto->message,
                    'raw_snippet' => $dto->snippet,
                    'status' => 'pending',
                ]);
            }, $parsedFindings));

            $this->scan->update([
                'status' => 'scoring',
                'total_findings' => $findings->count(),
            ]);

            // Acquire the source this scan refers to. On a hosted deployment
            // the code lives in someone else's repository, so this shallow
            // clones the exact commit; locally it may just be a directory.
            $workspace = $workspaces->for($this->scan);

            if (! $workspace->isAvailable()) {
                Log::warning('Enriching scan without source — AST and blame features will use defaults.', [
                    'scan_id' => $this->scan->id,
                    'driver' => $workspace->driver(),
                ]);
            }

            // Steps: AST enrichment -> feature vector assembly, in batch to
            // avoid N+1 Rule lookups.
            $vectorBuilder->buildBatch($findings, $workspace->path());

            // Rubix ML batch inference — one model load, one predict() call
            // over the entire dataset rather than per-finding overhead. During
            // cold start (no model trained yet) this scores nothing and the
            // findings queue up unscored for human labeling instead.
            $scoredCount = $triageService->predictBatch($findings);

            // Persist the exact AI input context now, while the source
            // workspace still exists — it gets released in `finally`
            // below, and AnalyzeFindingsWithAninoJob runs later on a
            // separate queue with no access to this checkout.
            foreach ($findings as $finding) {
                $finding->refresh();

                $snapshot = $aiContextBuilder->build(
                    $finding,
                    $workspace->path()
                );

                $finding->aiContext()->updateOrCreate(
                    [],
                    [
                        'source_commit' => $this->scan->commit_sha ?? null,
                        'context_hash' => $snapshot['hash'],
                        'metadata' => $snapshot['metadata'],
                        'context' => $snapshot['context'],
                    ]
                );
            }

            if (config('services.ollama.enabled') && $findings->isNotEmpty()) {
                $candidateIds = app(AninoCandidateSelector::class)
                    ->forScan($this->scan)
                    ->values()
                    ->all();

                if ($candidateIds !== []) {
                    $run = AninoAnalysisRun::create([
                        'scan_id' => $this->scan->id,
                        'status' => 'queued',
                        'phase' => 'queued',
                        'candidate_finding_ids' => $candidateIds,
                        'total_findings' => count($candidateIds),
                        'heartbeat_at' => now(),
                    ]);

                    AnalyzeFindingsWithAninoJob::dispatch($this->scan->id, $run->id, 0)
                        ->onQueue(config('services.ollama.queue', 'ai-analysis'));
                }
            }

            $suppressedCount = $findings
                ->filter(fn (Finding $f) => $f->predicted_label === 'false_positive' && $f->tp_probability <= 0.15)
                ->count();

            $this->scan->update([
                'status' => 'complete',
                'suppressed_count' => $suppressedCount,
            ]);

            if ($scoredCount === 0 && $findings->isNotEmpty()) {
                Log::info('Scan ingested without ML scoring — no trained model yet.', [
                    'scan_id' => $this->scan->id,
                    'findings' => $findings->count(),
                ]);
            }

            // Auto PR-comment step is intentionally a separate queued job
            // (PostPrCommentsJob) triggered from here so a VCS API outage
            // doesn't fail or retry the whole ingestion pipeline.
            if ($scoredCount > 0 && config('sast.pr_comments.enabled')) {
                PostPrCommentsJob::dispatch($this->scan)->onQueue('vcs-integrations');
            }

        } catch (\Throwable $e) {
            $this->scan->update(['status' => 'failed']);
            Log::error('SAST scan processing failed', [
                'scan_id' => $this->scan->id,
                'error' => $e->getMessage(),
            ]);
            throw $e;
        } finally {
            // Ephemeral checkouts must be deleted whether the scan succeeded,
            // failed, or threw mid-enrichment — otherwise a hosted deployment
            // accumulates clones of every repository it has ever scanned.
            $workspace?->release();
        }
    }
}
