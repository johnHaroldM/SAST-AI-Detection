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
use App\Services\AI\OllamaClient;
use App\Services\AI\OllamaUnavailableException;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Executes a persisted reviewer-major cursor over a scan. The first N steps
 * are ATAKE and the next N are DEPENSA, so only one large local model needs
 * to be resident at a time. Every invocation performs at most one reviewer
 * inference and then dispatches the next resumable unit of work.
 */
class AnalyzeFindingsWithAninoJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 3;

    public int $timeout;

    /** Nullable for queue payloads serialized before cursor expectations existed. */
    public ?int $expectedStep = null;

    public function __construct(
        public int $scanId,
        public ?int $runId = null,
        ?int $expectedStep = null,
    ) {
        $this->expectedStep = $expectedStep;
        $this->timeout = max(120, (int) config('services.ollama.job_timeout', 420));
    }

    /** @return list<int> */
    public function backoff(): array
    {
        return [15, 60, 180];
    }

    public function handle(
        AtakeReviewer $atake,
        DepensaReviewer $depensa,
        FindingAdjudicator $adjudicator,
        AninoCandidateSelector $selector,
        OllamaClient $ollama,
    ): void {
        $run = $this->run();

        if ($run && $this->isTerminal($run)) {
            return;
        }

        $runLock = Cache::lock(
            "anino-analysis-run:{$this->scanId}",
            $this->timeout + 60,
        );

        if (! $runLock->get()) {
            $this->handleLockContention($run);

            return;
        }

        try {
            // The run was initially read before taking the lock. Reload it now
            // so a duplicate queued job cannot replay a step that another
            // worker completed while this job was waiting for the lock.
            $run = $this->run();

            if ($run === null) {
                $run = AninoAnalysisRun::query()
                    ->where('scan_id', $this->scanId)
                    ->whereIn('status', ['queued', 'running', 'running_with_errors'])
                    ->oldest('id')
                    ->first();
                $this->runId = $run?->id;
            }

            if ($run && ($this->isTerminal($run) || $this->isObsolete($run))) {
                return;
            }

            if ($run && $this->skipSupersededRun($run)) {
                return;
            }

            $runtimeLock = Cache::lock(
                (string) config('services.ollama.runtime_lock', 'anino-ollama-runtime'),
                $this->timeout + 60,
            );

            if (! $runtimeLock->get()) {
                $this->redispatchAfterRuntimeContention($run);

                return;
            }

            try {
                $queueNext = $this->analyzeNext(
                    $run,
                    $atake,
                    $depensa,
                    $adjudicator,
                    $selector,
                    $ollama,
                );
            } finally {
                $runtimeLock->release();
            }
        } finally {
            $runLock->release();
        }

        if ($queueNext) {
            $continuedRun = $this->run();

            if ($continuedRun === null) {
                return;
            }

            self::dispatch($this->scanId, $this->runId, (int) $continuedRun->next_step)
                ->onQueue((string) config('services.ollama.queue', 'ai-analysis'));
        }
    }

    private function analyzeNext(
        ?AninoAnalysisRun $run,
        AtakeReviewer $atake,
        DepensaReviewer $depensa,
        FindingAdjudicator $adjudicator,
        AninoCandidateSelector $selector,
        OllamaClient $ollama,
    ): bool {
        $scan = Scan::query()->findOrFail($this->scanId);
        $run ??= $this->createRun($scan, $selector);
        $candidateIds = $this->candidateIds($run, $scan, $selector);
        $totalFindings = count($candidateIds);
        $totalSteps = $totalFindings * 2;
        $step = min($totalSteps, max(0, (int) $run->next_step));

        if ($candidateIds === [] || $step >= $totalSteps) {
            $this->completeRun($run, $candidateIds);

            return false;
        }

        $reviewer = $step < $totalFindings ? 'atake' : 'depensa';
        $findingIndex = $step % $totalFindings;
        $model = (string) config("services.ollama.models.{$reviewer}");
        $finding = Finding::query()
            ->with('aiContext')
            ->where('scan_id', $scan->id)
            ->findOrFail($candidateIds[$findingIndex]);
        $isStarting = $run->started_at === null;

        $this->markRun($run, [
            'status' => $this->hasStepErrors($candidateIds, $step)
                ? 'running_with_errors'
                : 'running',
            'phase' => $reviewer,
            'current_finding_id' => $finding->id,
            'started_at' => $run->started_at ?? now(),
            'heartbeat_at' => now(),
            'phase_started_at' => now(),
        ]);

        if ($isStarting) {
            Log::info('ANINO scan analysis started', [
                'scan_id' => $scan->id,
                'run_id' => $run->id,
                'findings' => $totalFindings,
                'steps' => $totalSteps,
            ]);
        }

        $stepError = null;

        try {
            $this->reviewStep($run, $finding, $reviewer, $model, $atake, $depensa);
        } catch (OllamaUnavailableException $e) {
            $this->logReviewerFailure($run, $finding, $reviewer, $e);
            $this->terminateUnavailable($run, $finding, $candidateIds, $e);

            return false;
        } catch (Throwable $e) {
            $stepError = strtoupper($reviewer).': '.$e->getMessage();
            $this->logReviewerFailure($run, $finding, $reviewer, $e);
        }

        $reviewed = false;

        if ($reviewer === 'depensa') {
            if (
                $this->completedAssessment($finding, 'atake', (string) config('services.ollama.models.atake'))
                && $this->completedAssessment($finding, 'depensa', (string) config('services.ollama.models.depensa'))
            ) {
                $this->markPhase($run, 'adjudicator', $finding);
                $adjudicator->update($finding);
            }

            $reviewed = $finding->aiAssessments()
                ->where('reviewer', 'adjudicator')
                ->whereNotNull('completed_at')
                ->exists();
        }

        $nextStep = $step + 1;

        if (
            $nextStep === $totalFindings
            && config('services.ollama.models.atake') !== config('services.ollama.models.depensa')
        ) {
            $this->safeUnload($ollama, (string) config('services.ollama.models.atake'), $run, 'atake');
        }

        if ($nextStep === $totalSteps) {
            $this->safeUnload($ollama, (string) config('services.ollama.models.depensa'), $run, 'depensa');
        }

        $progress = $this->progressCounts($candidateIds, $nextStep);
        $hasErrors = $this->hasStepErrors($candidateIds, $nextStep);
        $complete = $nextStep >= $totalSteps;

        $this->markRun($run, [
            'status' => $complete
                ? ($progress['failed'] > 0 ? 'complete_with_errors' : 'complete')
                : ($hasErrors ? 'running_with_errors' : 'running'),
            'phase' => $complete ? 'complete' : $this->phaseForStep($nextStep, $totalFindings),
            'current_finding_id' => $complete
                ? null
                : $candidateIds[$nextStep % $totalFindings],
            'next_step' => $nextStep,
            'processed_findings' => $progress['processed'],
            'reviewed_findings' => $progress['reviewed'],
            'failed_findings' => $progress['failed'],
            'last_error' => $stepError ?? $run->last_error,
            'heartbeat_at' => now(),
            'phase_started_at' => now(),
            'completed_at' => $complete ? now() : null,
        ]);

        if ($reviewer === 'depensa') {
            Log::{$reviewed ? 'info' : 'error'}(
                $reviewed ? 'ANINO finding analysis completed' : 'ANINO finding analysis failed',
                [
                    'finding_id' => $finding->id,
                    'scan_id' => $finding->scan_id,
                    'run_id' => $run->id,
                    'processed' => $progress['processed'],
                    'total' => $totalFindings,
                    'error' => $reviewed ? null : ($stepError ?? 'One or both reviewer results are missing.'),
                ],
            );
        }

        if ($complete) {
            Log::info('ANINO scan analysis completed', [
                'scan_id' => $scan->id,
                'run_id' => $run->id,
                'reviewed' => $progress['reviewed'],
                'failed' => $progress['failed'],
            ]);
        }

        return ! $complete;
    }

    private function reviewStep(
        AninoAnalysisRun $run,
        Finding $finding,
        string $reviewer,
        string $model,
        AtakeReviewer $atake,
        DepensaReviewer $depensa,
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

        $startedAt = microtime(true);

        Log::info('ANINO reviewer started', [
            'finding_id' => $finding->id,
            'scan_id' => $finding->scan_id,
            'run_id' => $run->id,
            'reviewer' => $reviewer,
            'model' => $model,
        ]);

        $keepAlive = (string) config('services.ollama.phase_keep_alive', '5m');
        $result = $reviewer === 'atake'
            ? $atake->review($finding, $keepAlive)
            : $depensa->review($finding, $keepAlive);

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
            ->where('prompt_version', $this->promptVersion($reviewer))
            ->where('context_hash', $finding->aiContext?->context_hash)
            ->whereNotNull('completed_at')
            ->latest('completed_at')
            ->first();
    }

    private function promptVersion(string $reviewer): string
    {
        return $reviewer === 'atake'
            ? AtakeReviewer::PROMPT_VERSION
            : DepensaReviewer::PROMPT_VERSION;
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

    /** @param list<int> $candidateIds */
    private function terminateUnavailable(
        AninoAnalysisRun $run,
        Finding $finding,
        array $candidateIds,
        OllamaUnavailableException $error,
    ): void {
        $reviewed = AiAssessment::query()
            ->whereIn('finding_id', $candidateIds)
            ->where('reviewer', 'adjudicator')
            ->whereNotNull('completed_at')
            ->distinct()
            ->count('finding_id');

        $this->markRun($run, [
            'status' => 'failed',
            'phase' => 'unavailable',
            'current_finding_id' => $finding->id,
            'reviewed_findings' => $reviewed,
            'failed_findings' => max(0, count($candidateIds) - $reviewed),
            'last_error' => $error->getMessage().' Remaining findings were not attempted.',
            'heartbeat_at' => now(),
            'phase_started_at' => now(),
            'completed_at' => now(),
        ]);

        Log::warning('ANINO scan analysis stopped because Ollama is unavailable', [
            'scan_id' => $run->scan_id,
            'run_id' => $run->id,
            'finding_id' => $finding->id,
            'next_step' => $run->next_step,
        ]);
    }

    private function safeUnload(
        OllamaClient $ollama,
        string $model,
        AninoAnalysisRun $run,
        string $reviewer,
    ): void {
        try {
            $ollama->unload($model);

            Log::info('ANINO reviewer model unloaded', [
                'scan_id' => $run->scan_id,
                'run_id' => $run->id,
                'reviewer' => $reviewer,
                'model' => $model,
            ]);
        } catch (Throwable $error) {
            Log::warning('ANINO reviewer model could not be unloaded', [
                'scan_id' => $run->scan_id,
                'run_id' => $run->id,
                'reviewer' => $reviewer,
                'error' => $error->getMessage(),
            ]);
        }
    }

    /**
     * @param  list<int>  $candidateIds
     * @return array{processed:int,reviewed:int,failed:int}
     */
    private function progressCounts(array $candidateIds, int $nextStep): array
    {
        $totalFindings = count($candidateIds);
        $processed = max(0, min($totalFindings, $nextStep - $totalFindings));
        $processedIds = array_slice($candidateIds, 0, $processed);
        $reviewed = $processedIds === []
            ? 0
            : AiAssessment::query()
                ->whereIn('finding_id', $processedIds)
                ->where('reviewer', 'adjudicator')
                ->whereNotNull('completed_at')
                ->distinct()
                ->count('finding_id');

        return [
            'processed' => $processed,
            'reviewed' => $reviewed,
            'failed' => max(0, $processed - $reviewed),
        ];
    }

    /** @param list<int> $candidateIds */
    private function hasStepErrors(array $candidateIds, int $nextStep): bool
    {
        $totalFindings = count($candidateIds);

        if ($totalFindings === 0 || $nextStep === 0) {
            return false;
        }

        $atakeSteps = min($totalFindings, $nextStep);
        $depensaSteps = max(0, min($totalFindings, $nextStep - $totalFindings));

        return $this->completedReviewerCount(
            array_slice($candidateIds, 0, $atakeSteps),
            'atake',
            (string) config('services.ollama.models.atake'),
        ) < $atakeSteps
            || $this->completedReviewerCount(
                array_slice($candidateIds, 0, $depensaSteps),
                'depensa',
                (string) config('services.ollama.models.depensa'),
            ) < $depensaSteps;
    }

    /** @param list<int> $findingIds */
    private function completedReviewerCount(array $findingIds, string $reviewer, string $model): int
    {
        if ($findingIds === []) {
            return 0;
        }

        return AiAssessment::query()
            ->whereIn('finding_id', $findingIds)
            ->where('reviewer', $reviewer)
            ->where('model', $model)
            ->whereNotNull('completed_at')
            ->distinct()
            ->count('finding_id');
    }

    private function phaseForStep(int $step, int $totalFindings): string
    {
        return $step < $totalFindings ? 'atake' : 'depensa';
    }

    /** @return list<int> */
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
            'next_step' => 0,
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
            'next_step' => 0,
            'total_findings' => count($candidateIds),
            'heartbeat_at' => now(),
        ]);
        $this->runId = $run->id;

        return $run;
    }

    /** @param list<int> $candidateIds */
    private function completeRun(AninoAnalysisRun $run, array $candidateIds): void
    {
        $progress = $this->progressCounts($candidateIds, count($candidateIds) * 2);

        $this->markRun($run, [
            'status' => $progress['failed'] > 0 ? 'complete_with_errors' : 'complete',
            'phase' => 'complete',
            'current_finding_id' => null,
            'next_step' => count($candidateIds) * 2,
            'processed_findings' => $progress['processed'],
            'reviewed_findings' => $progress['reviewed'],
            'failed_findings' => $progress['failed'],
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
            ->whereIn('status', ['queued', 'running', 'running_with_errors'])
            ->oldest('id')
            ->first();

        if ($run && $otherRun && $otherRun->id < $run->id) {
            $this->markRun($run, [
                'status' => 'skipped',
                'phase' => 'locked',
                'last_error' => 'Another ATAKE/DEPENSA review is already running for this scan.',
                'heartbeat_at' => now(),
                'completed_at' => now(),
            ]);
        }

        Log::warning('ANINO scan analysis deferred because another worker holds the run lock', [
            'scan_id' => $this->scanId,
            'run_id' => $this->runId,
            'owner_run_id' => $otherRun?->id,
        ]);
    }

    private function skipSupersededRun(AninoAnalysisRun $run): bool
    {
        $predecessor = AninoAnalysisRun::query()
            ->where('scan_id', $run->scan_id)
            ->whereKeyNot($run->id)
            ->where('id', '<', $run->id)
            ->whereIn('status', ['queued', 'running', 'running_with_errors'])
            ->oldest('id')
            ->first();

        if ($predecessor === null) {
            return false;
        }

        $this->markRun($run, [
            'status' => 'skipped',
            'phase' => 'superseded',
            'last_error' => "Run {$predecessor->id} already owns this scan's AI review.",
            'heartbeat_at' => now(),
            'completed_at' => now(),
        ]);

        return true;
    }

    private function redispatchAfterRuntimeContention(?AninoAnalysisRun $run): void
    {
        if ($run === null || $this->isTerminal($run) || $this->isObsolete($run)) {
            return;
        }

        self::dispatch($this->scanId, $run->id, (int) $run->next_step)
            ->delay(now()->addSeconds(15))
            ->onQueue((string) config('services.ollama.queue', 'ai-analysis'));

        Log::info('ANINO review waiting for the shared Ollama runtime', [
            'scan_id' => $this->scanId,
            'run_id' => $run->id,
            'next_step' => $run->next_step,
        ]);
    }

    private function isObsolete(AninoAnalysisRun $run): bool
    {
        $expectedStep = $this->expectedStep ?? null;

        return $expectedStep !== null
            && (int) $run->next_step !== $expectedStep;
    }

    private function isTerminal(AninoAnalysisRun $run): bool
    {
        return in_array($run->status, ['complete', 'complete_with_errors', 'failed', 'skipped'], true);
    }

    public function failed(Throwable $e): void
    {
        $run = $this->run();

        if ($run === null || $this->isTerminal($run) || $this->isObsolete($run)) {
            return;
        }

        $this->markRun($run, [
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

    /** @param array<string, mixed> $attributes */
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
                'model' => $review['model'],
                'prompt_version' => $review['prompt_version'],
                'context_hash' => $finding->aiContext?->context_hash,
            ],
            [
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
                'usage' => $review['usage'],
                'raw_response' => $review['raw'],
                'completed_at' => now(),
            ],
        );
    }

    private function normalizeConfidence(mixed $confidence): ?float
    {
        if (! is_numeric($confidence)) {
            return null;
        }

        $normalized = (float) $confidence;

        if ($normalized > 1) {
            $normalized /= 100;
        }

        return round(min(1, max(0, $normalized)), 4);
    }
}
