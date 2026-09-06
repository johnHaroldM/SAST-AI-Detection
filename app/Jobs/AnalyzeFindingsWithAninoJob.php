<?php

namespace App\Jobs;

use App\Models\AiAssessment;
use App\Models\AninoAnalysisRun;
use App\Models\Finding;
use App\Models\Scan;
use App\Services\AI\AiEvaluationOutcome;
use App\Services\AI\AninoCandidateSelector;
use App\Services\AI\AtakeReviewer;
use App\Services\AI\DepensaReviewer;
use App\Services\AI\FindingAdjudicator;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Reviews one finding per invocation and dispatches the next unit of work.
 * Small, resumable jobs keep long local Ollama inference from turning a
 * complete scan review into one fragile queue reservation.
 */
class AnalyzeFindingsWithAninoJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 1;

    public int $timeout;

    public function __construct(
        public int $scanId,
        public ?int $runId = null,
    ) {
        $this->timeout = max(120, (int) config('services.ollama.job_timeout', 420));
    }

    public function handle(
        AtakeReviewer $atake,
        DepensaReviewer $depensa,
        FindingAdjudicator $adjudicator,
        AninoCandidateSelector $selector,
    ): void {
        $run = $this->run();

        if ($run && $this->isTerminal($run)) {
            return;
        }

        $lock = Cache::lock(
            "anino-analysis-run:{$this->scanId}",
            $this->timeout + 60
        );

        if (! $lock->get()) {
            $this->handleLockContention($run);

            return;
        }

        try {
            $queueNext = $this->analyzeNext(
                $run,
                $atake,
                $depensa,
                $adjudicator,
                $selector,
            );
        } finally {
            $lock->release();
        }

        if ($queueNext) {
            self::dispatch($this->scanId, $this->runId)
                ->onQueue((string) config('services.ollama.queue', 'ai-analysis'));
        }
    }

    private function analyzeNext(
        ?AninoAnalysisRun $run,
        AtakeReviewer $atake,
        DepensaReviewer $depensa,
        FindingAdjudicator $adjudicator,
        AninoCandidateSelector $selector,
    ): bool {
        $scan = Scan::query()->findOrFail($this->scanId);
        $run ??= $this->createRun($scan, $selector);
        $candidateIds = $this->candidateIds($run, $scan, $selector);
        $processed = min((int) $run->processed_findings, count($candidateIds));

        if ($candidateIds === [] || $processed >= count($candidateIds)) {
            $this->completeRun($run);

            return false;
        }

        $finding = Finding::query()
            ->with('aiContext')
            ->where('scan_id', $scan->id)
            ->findOrFail($candidateIds[$processed]);
        $isStarting = $run->started_at === null;

        $this->markRun($run, [
            'status' => (int) $run->failed_findings > 0 ? 'running_with_errors' : 'running',
            'phase' => 'starting',
            'current_finding_id' => $finding->id,
            'started_at' => $run->started_at ?? now(),
            'heartbeat_at' => now(),
            'phase_started_at' => now(),
        ]);

        if ($isStarting) {
            Log::info('ANINO scan analysis started', [
                'scan_id' => $scan->id,
                'run_id' => $run->id,
                'findings' => count($candidateIds),
            ]);
        }

        $errors = [];

        try {
            $this->reviewWith(
                $run,
                $finding,
                'atake',
                (string) config('services.ollama.models.atake'),
                fn () => $atake->review($finding),
            );
        } catch (Throwable $e) {
            $errors[] = 'ATAKE: '.$e->getMessage();
            $this->logReviewerFailure($run, $finding, 'atake', $e);
        }

        try {
            $this->reviewWith(
                $run,
                $finding,
                'depensa',
                (string) config('services.ollama.models.depensa'),
                fn () => $depensa->review($finding),
            );
        } catch (Throwable $e) {
            $errors[] = 'DEPENSA: '.$e->getMessage();
            $this->logReviewerFailure($run, $finding, 'depensa', $e);
        }

        $reviewed = false;

        if (
            $this->completedAssessment($finding, 'atake', (string) config('services.ollama.models.atake'))
            && $this->completedAssessment($finding, 'depensa', (string) config('services.ollama.models.depensa'))
        ) {
            $this->markPhase($run, 'adjudicator', $finding);
            $adjudicator->update($finding);
            $reviewed = $finding->aiAssessments()
                ->where('reviewer', 'adjudicator')
                ->whereNotNull('completed_at')
                ->exists();
        }

        if (! $reviewed && $errors === []) {
            $errors[] = 'The finding could not be adjudicated because one or both reviewer results are missing.';
        }

        $nextProcessed = $processed + 1;
        $nextReviewed = (int) $run->reviewed_findings + ($reviewed ? 1 : 0);
        $nextFailed = (int) $run->failed_findings + ($reviewed ? 0 : 1);
        $complete = $nextProcessed >= count($candidateIds);

        $this->markRun($run, [
            'status' => $complete
                ? ($nextFailed > 0 ? 'complete_with_errors' : 'complete')
                : ($nextFailed > 0 ? 'running_with_errors' : 'running'),
            'phase' => $complete ? 'complete' : 'queued',
            'current_finding_id' => $complete ? null : $finding->id,
            'processed_findings' => $nextProcessed,
            'reviewed_findings' => $nextReviewed,
            'failed_findings' => $nextFailed,
            'last_error' => $errors === [] ? $run->last_error : implode(' | ', $errors),
            'heartbeat_at' => now(),
            'phase_started_at' => now(),
            'completed_at' => $complete ? now() : null,
        ]);

        $logMethod = $reviewed ? 'info' : 'error';
        Log::$logMethod(
            $reviewed ? 'ANINO finding analysis completed' : 'ANINO finding analysis failed',
            [
                'finding_id' => $finding->id,
                'scan_id' => $finding->scan_id,
                'run_id' => $run->id,
                'processed' => $nextProcessed,
                'total' => count($candidateIds),
                'error' => $errors === [] ? null : implode(' | ', $errors),
            ]
        );

        if ($complete) {
            Log::info('ANINO scan analysis completed', [
                'scan_id' => $scan->id,
                'run_id' => $run->id,
                'reviewed' => $nextReviewed,
                'failed' => $nextFailed,
            ]);
        }

        return ! $complete;
    }

    /**
     * @param  callable(): array{
     *     reviewer: string,
     *     model: string,
     *     prompt_version: string,
     *     result: array<string, mixed>,
     *     usage: array<string, mixed>,
     *     raw: array<string, mixed>
     * }  $review
     */
    private function reviewWith(
        AninoAnalysisRun $run,
        Finding $finding,
        string $reviewer,
        string $model,
        callable $review,
    ): void {
        if ($this->completedAssessment($finding, $reviewer, $model)) {
            Log::info('ANINO reviewer result reused', [
                'finding_id' => $finding->id,
                'scan_id' => $finding->scan_id,
                'run_id' => $run->id,
                'reviewer' => $reviewer,
            ]);

            return;
        }

        $this->markPhase($run, $reviewer, $finding);
        $startedAt = microtime(true);

        Log::info('ANINO reviewer started', [
            'finding_id' => $finding->id,
            'scan_id' => $finding->scan_id,
            'run_id' => $run->id,
            'reviewer' => $reviewer,
            'model' => $model,
        ]);

        $result = $review();
        $this->storeAssessment($finding, $result);

        Log::info('ANINO reviewer completed', [
            'finding_id' => $finding->id,
            'scan_id' => $finding->scan_id,
            'run_id' => $run->id,
            'reviewer' => $reviewer,
            'duration_seconds' => round(microtime(true) - $startedAt, 1),
            'prompt_tokens' => data_get($result, 'usage.prompt_eval_count'),
            'output_tokens' => data_get($result, 'usage.eval_count'),
        ]);
    }

    private function completedAssessment(Finding $finding, string $reviewer, string $model): ?AiAssessment
    {
        return $finding->aiAssessments()
            ->where('reviewer', $reviewer)
            ->where('model', $model)
            ->whereNotNull('completed_at')
            ->latest('completed_at')
            ->first();
    }

    private function markPhase(AninoAnalysisRun $run, string $phase, Finding $finding): void
    {
        $this->markRun($run, [
            'phase' => $phase,
            'current_finding_id' => $finding->id,
            'heartbeat_at' => now(),
            'phase_started_at' => now(),
        ]);
    }

    private function logReviewerFailure(
        AninoAnalysisRun $run,
        Finding $finding,
        string $reviewer,
        Throwable $error,
    ): void {
        $this->markRun($run, [
            'status' => 'running_with_errors',
            'last_error' => strtoupper($reviewer).': '.$error->getMessage(),
            'heartbeat_at' => now(),
        ]);

        Log::error('ANINO reviewer failed', [
            'finding_id' => $finding->id,
            'scan_id' => $finding->scan_id,
            'run_id' => $run->id,
            'reviewer' => $reviewer,
            'error' => $error->getMessage(),
        ]);
    }

    /**
     * @return list<int>
     */
    private function candidateIds(
        AninoAnalysisRun $run,
        Scan $scan,
        AninoCandidateSelector $selector,
    ): array {
        $candidateIds = array_values(array_map('intval', $run->candidate_finding_ids ?? []));

        if ($candidateIds !== []) {
            return $candidateIds;
        }

        $candidateIds = array_values($selector->forScan($scan)->all());
        $this->markRun($run, [
            'candidate_finding_ids' => $candidateIds,
            'total_findings' => count($candidateIds),
        ]);

        return $candidateIds;
    }

    private function createRun(Scan $scan, AninoCandidateSelector $selector): AninoAnalysisRun
    {
        $candidateIds = $selector->forScan($scan)->values()->all();
        $run = AninoAnalysisRun::query()->create([
            'scan_id' => $scan->id,
            'status' => 'queued',
            'phase' => 'queued',
            'candidate_finding_ids' => $candidateIds,
            'total_findings' => count($candidateIds),
            'heartbeat_at' => now(),
        ]);
        $this->runId = $run->id;

        return $run;
    }

    private function completeRun(AninoAnalysisRun $run): void
    {
        $this->markRun($run, [
            'status' => (int) $run->failed_findings > 0 ? 'complete_with_errors' : 'complete',
            'phase' => 'complete',
            'current_finding_id' => null,
            'heartbeat_at' => now(),
            'phase_started_at' => now(),
            'completed_at' => now(),
        ]);
    }

    private function handleLockContention(?AninoAnalysisRun $run): void
    {
        $otherRun = AninoAnalysisRun::query()
            ->where('scan_id', $this->scanId)
            ->when($run, fn ($query) => $query->whereKeyNot($run->id))
            ->whereIn('status', ['running', 'running_with_errors'])
            ->latest('heartbeat_at')
            ->first();

        if ($run && $run->status === 'queued' && $otherRun) {
            $this->markRun($run, [
                'status' => 'skipped',
                'phase' => 'locked',
                'last_error' => 'Another ATAKE/DEPENSA review is already running for this scan.',
                'heartbeat_at' => now(),
                'completed_at' => now(),
            ]);
        } elseif ($this->job !== null) {
            $this->release(15);
        }

        Log::warning('ANINO scan analysis deferred because another worker holds the run lock', [
            'scan_id' => $this->scanId,
            'run_id' => $this->runId,
            'owner_run_id' => $otherRun?->id,
        ]);
    }

    private function isTerminal(AninoAnalysisRun $run): bool
    {
        return in_array($run->status, ['complete', 'complete_with_errors', 'failed', 'skipped'], true);
    }

    public function failed(Throwable $e): void
    {
        $this->markRun($this->run(), [
            'status' => 'failed',
            'phase' => 'failed',
            'last_error' => $e->getMessage(),
            'heartbeat_at' => now(),
            'phase_started_at' => now(),
            'completed_at' => now(),
        ]);
    }

    private function run(): ?AninoAnalysisRun
    {
        if ($this->runId === null) {
            return null;
        }

        return AninoAnalysisRun::query()->find($this->runId);
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function markRun(?AninoAnalysisRun $run, array $attributes): void
    {
        $run?->update($attributes);
    }

    /**
     * @param array{
     *     reviewer: string,
     *     model: string,
     *     prompt_version: string,
     *     result: array<string, mixed>,
     *     usage: array<string, mixed>,
     *     raw: array<string, mixed>
     * } $review
     */
    private function storeAssessment(Finding $finding, array $review): void
    {
        $result = $review['result'];

        AiAssessment::query()->updateOrCreate(
            [
                'finding_id' => $finding->id,
                'reviewer' => $review['reviewer'],
                'prompt_version' => $review['prompt_version'],
            ],
            [
                'model' => $review['model'],
                'classification' => $result['classification'],
                'evaluation_outcome' => AiEvaluationOutcome::classify(
                    $finding->predicted_label,
                    $result['classification'],
                ),
                'confidence' => $this->normalizeConfidence($result['confidence'] ?? null),
                'attacker_controlled' => $result['attacker_controlled'],
                'sink_reachable' => $result['sink_reachable'],
                'mitigation_detected' => $result['mitigation_detected'],
                'preconditions' => $result['preconditions'],
                'supporting_evidence' => $result['supporting_evidence'],
                'contradicting_evidence' => $result['contradicting_evidence'],
                'missing_evidence' => $result['missing_evidence'],
                'remediation' => $result['remediation'],
                'reasoning_summary' => $result['reasoning_summary'],
                'context_hash' => $finding->aiContext?->context_hash,
                'usage' => $review['usage'],
                'raw_response' => $review['raw'],
                'completed_at' => now(),
            ]
        );
    }

    private function normalizeConfidence(mixed $confidence): ?float
    {
        if (! is_numeric($confidence)) {
            return null;
        }

        $normalized = (float) $confidence;

        if ($normalized > 1) {
            $normalized = $normalized / 100;
        }

        return round(min(1, max(0, $normalized)), 4);
    }
}
