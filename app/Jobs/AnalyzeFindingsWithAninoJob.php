<?php

namespace App\Jobs;

use App\Models\AiAssessment;
use App\Models\Finding;
use App\Models\Scan;
use App\Services\AI\AtakeReviewer;
use App\Services\AI\DepensaReviewer;
use App\Services\AI\FindingAdjudicator;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

/**
 * Runs after ProcessScanJob, on the `ai-analysis` queue. Reviews every
 * finding on the scan that has a persisted FindingAiContext, one at a
 * time: ATAKE then DEPENSA independently, then FindingAdjudicator
 * reconciles the two into a combined view. A failure on one finding is
 * logged and skipped rather than failing the whole batch — one bad
 * Ollama response shouldn't block the rest of the scan's findings.
 *
 * Chunked via chunkById (ANINO_AI_BATCH_SIZE) rather than loaded all at
 * once, since large scans can have thousands of findings.
 *
 * Depends on AtakeReviewer, DepensaReviewer, and FindingAdjudicator
 * (Phase 4) — until those exist, dispatching this job will fail when
 * the queue worker picks it up, not at dispatch time. Keep
 * ANINO_AI_ENABLED=false until Phase 4 ships if ProcessScanJob is
 * running against real scans in the meantime.
 */
class AnalyzeFindingsWithAninoJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 2;

    public int $timeout = 1800;

    public function __construct(
        public int $scanId
    ) {}

    public function handle(
        AtakeReviewer $atake,
        DepensaReviewer $depensa,
        FindingAdjudicator $adjudicator,
    ): void {
        $scan = Scan::query()->findOrFail($this->scanId);

        Finding::query()
            ->where('scan_id', $scan->id)
            ->whereHas('aiContext')
            ->with('aiContext')
            ->chunkById(
                (int) config('services.ollama.batch_size', 10),
                function ($findings) use ($atake, $depensa, $adjudicator) {
                    foreach ($findings as $finding) {
                        try {
                            $atakeReview = $atake->review($finding);
                            $this->storeAssessment($finding, $atakeReview);

                            $depensaReview = $depensa->review($finding);
                            $this->storeAssessment($finding, $depensaReview);

                            $adjudicator->update($finding);
                        } catch (\Throwable $e) {
                            Log::error('ANINO finding analysis failed', [
                                'finding_id' => $finding->id,
                                'scan_id' => $finding->scan_id,
                                'error' => $e->getMessage(),
                            ]);

                            // Continue analyzing other findings.
                        }
                    }
                }
            );
    }

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
                'confidence' => $result['confidence'],
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
}
