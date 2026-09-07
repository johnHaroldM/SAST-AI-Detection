<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreScanRequest;
use App\Models\AiAssessment;
use App\Models\AninoAnalysisRun;
use App\Models\Scan;
use App\Services\AI\AiEvaluationOutcome;
use App\Services\AI\AiTrainingPromoter;
use App\Services\AI\AninoCandidateSelector;
use App\Services\AI\AninoRunManager;
use App\Services\AI\AtakeReviewer;
use App\Services\AI\DepensaReviewer;
use App\Services\ScanIngestionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;

class ScanController extends Controller
{
    /**
     * POST /api/scans
     * Accepts a raw SARIF/scanner JSON report, persists it, and dispatches
     * the async ingestion pipeline. Returns immediately with a scan ID —
     * parsing, feature extraction, and ML scoring all happen in the queue
     * so this endpoint stays fast even for large monorepo scans.
     */
    public function store(StoreScanRequest $request, ScanIngestionService $ingestion): JsonResponse
    {
        $scan = $ingestion->ingest($request->validated(), $request->file('report'));

        return response()->json([
            'scan_id' => $scan->id,
            'status' => $scan->status,
            'message' => 'Scan queued for AST enrichment and ML triage.',
        ], 202);
    }

    /**
     * GET /api/scans/{scan}
     * Poll endpoint for the async pipeline's progress + summary counts.
     */
    public function show(Scan $scan): JsonResponse
    {
        $scan->loadCount([
            'findings',
            'findings as true_positive_count' => fn ($q) => $q->where('predicted_label', 'true_positive'),
            'findings as false_positive_count' => fn ($q) => $q->where('predicted_label', 'false_positive'),
            'findings as pending_triage_count' => fn ($q) => $q->where('status', 'pending'),
        ]);

        return response()->json($scan);
    }

    /**
     * GET /api/scans/{scan}/findings
     * Paginated, filterable list of findings for the triage UI.
     * Supports filtering by predicted_label, min confidence, and status
     * so the frontend can show e.g. "only unreviewed high-confidence TPs".
     */
    public function findings(Scan $scan, Request $request): JsonResponse
    {
        $query = $scan->findings()->with('rule');

        if ($label = $request->query('predicted_label')) {
            $query->where('predicted_label', $label);
        }

        if ($minConfidence = $request->query('min_confidence')) {
            $query->where('tp_probability', '>=', (float) $minConfidence);
        }

        if ($status = $request->query('status')) {
            $query->where('status', $status);
        }

        return response()->json(
            $query->orderByDesc('tp_probability')->paginate(50)
        );
    }

    public function aninoStatus(
        Scan $scan,
        AiTrainingPromoter $trainingPromoter,
        AninoCandidateSelector $candidateSelector,
        AninoRunManager $runManager,
    ): JsonResponse {
        $total = $scan->findings()->count();
        $contexts = $scan->findings()->whereHas('aiContext')->count();

        $reviewCounts = AiAssessment::query()
            ->whereIn('finding_id', $scan->findings()->select('id'))
            ->selectRaw('reviewer, count(distinct finding_id) as total')
            ->groupBy('reviewer')
            ->pluck('total', 'reviewer');

        $recentAssessments = AiAssessment::query()
            ->whereIn('finding_id', $scan->findings()->select('id'))
            ->with('finding:id,predicted_label')
            ->latest('completed_at')
            ->limit(12)
            ->get(['id', 'finding_id', 'reviewer', 'classification', 'confidence', 'completed_at'])
            ->map(fn (AiAssessment $assessment) => [
                'time' => $assessment->completed_at?->format('H:i:s'),
                'level' => 'info',
                'message' => strtoupper($assessment->reviewer).' completed finding #'.$assessment->finding_id,
                'detail' => implode(' | ', [
                    $assessment->classification,
                    $this->outcomeAbbreviation(AiEvaluationOutcome::classify(
                        $assessment->finding?->predicted_label,
                        $assessment->classification,
                    )),
                    round((float) $assessment->confidence * 100).'%',
                ]),
            ]);

        $activeRun = $runManager->active($scan);
        $run = $activeRun ?? $scan->aninoAnalysisRuns()->latest('id')->first();
        $terminal = $run !== null && in_array(
            $run->status,
            ['complete', 'complete_with_errors', 'failed', 'skipped'],
            true,
        );
        $retryableFindings = $run !== null && in_array($run->status, ['complete_with_errors', 'failed'], true)
            ? $candidateSelector->failedFromRun($run)->count()
            : 0;
        $candidateIds = array_values(array_map('intval', $run->candidate_finding_ids ?? []));
        $runReviewCounts = $candidateIds === []
            ? collect()
            : AiAssessment::query()
                ->whereIn('finding_id', $candidateIds)
                ->whereIn('reviewer', ['atake', 'depensa'])
                ->where(function ($query) {
                    $query
                        ->where(fn ($review) => $review
                            ->where('reviewer', 'atake')
                            ->where('model', config('services.ollama.models.atake')))
                        ->orWhere(fn ($review) => $review
                            ->where('reviewer', 'depensa')
                            ->where('model', config('services.ollama.models.depensa')));
                })
                ->selectRaw('reviewer, count(distinct finding_id) as total')
                ->groupBy('reviewer')
                ->pluck('total', 'reviewer');
        $totalSteps = max(0, (int) ($run->total_findings ?? 0) * 2);
        $legacyCompletedSteps = $candidateIds === []
            ? min($totalSteps, ((int) ($run->processed_findings ?? 0) * 2) + $this->phaseStep($run?->phase))
            : min($totalSteps, (int) $runReviewCounts->sum());
        $completedSteps = min($totalSteps, max(
            $legacyCompletedSteps,
            (int) ($run->next_step ?? 0),
        ));
        $averageSeconds = $this->averageInferenceSeconds($scan);
        $remainingSeconds = $terminal
            ? 0
            : ($averageSeconds === null
            ? null
            : (int) round(max(0, $totalSteps - $completedSteps) * $averageSeconds));

        $logs = collect($this->recentAninoLogLines($scan, $run))
            ->merge($recentAssessments)
            ->sortByDesc('time')
            ->take(20)
            ->values();

        return response()->json([
            'enabled' => (bool) config('services.ollama.enabled'),
            'total_findings' => $total,
            'contexts' => $contexts,
            'atake' => (int) ($reviewCounts['atake'] ?? 0),
            'depensa' => (int) ($reviewCounts['depensa'] ?? 0),
            'adjudicated' => (int) ($reviewCounts['adjudicator'] ?? 0),
            'outcomes' => $this->outcomeMatrix($scan),
            'human_outcomes' => $this->humanOutcomeMatrix($scan),
            'retryable_findings' => $retryableFindings,
            'training_candidates' => $trainingPromoter->eligibleCount($scan),
            'training_promoted' => $trainingPromoter->promotedCount($scan),
            'training_threshold' => $trainingPromoter->threshold(),
            'run' => $run ? [
                'id' => $run->id,
                'status' => $run->status,
                'phase' => $run->phase,
                'current_finding_id' => $run->current_finding_id,
                'next_step' => $run->next_step,
                'processed_findings' => $run->processed_findings,
                'reviewed_findings' => $run->reviewed_findings,
                'failed_findings' => $run->failed_findings,
                'total_findings' => $run->total_findings,
                'remaining_findings' => max(0, $run->total_findings - $run->processed_findings),
                'completed_steps' => $completedSteps,
                'total_steps' => $totalSteps,
                'progress_percent' => $totalSteps > 0
                    ? (int) floor(($completedSteps / $totalSteps) * 100)
                    : 0,
                'average_seconds_per_review' => $averageSeconds === null ? null : (int) round($averageSeconds),
                'estimated_remaining_seconds' => $remainingSeconds,
                'last_error' => $run->last_error,
                'heartbeat_at' => $run->heartbeat_at?->toDateTimeString(),
                'heartbeat_age_seconds' => $run->heartbeat_at ? (int) $run->heartbeat_at->diffInSeconds(now()) : null,
                'phase_started_at' => $run->phase_started_at?->toDateTimeString(),
                'phase_elapsed_seconds' => $run->phase_started_at ? (int) $run->phase_started_at->diffInSeconds(now()) : null,
                'started_at' => $run->started_at?->toDateTimeString(),
                'completed_at' => $run->completed_at?->toDateTimeString(),
            ] : null,
            'queue' => [
                'ai_analysis' => DB::table('jobs')
                    ->where('queue', config('services.ollama.queue', 'ai-analysis'))
                    ->count(),
                'failed_ai_analysis' => DB::table('failed_jobs')
                    ->where('queue', config('services.ollama.queue', 'ai-analysis'))
                    ->count(),
            ],
            'complete' => $terminal || ($total > 0 && (int) ($reviewCounts['adjudicator'] ?? 0) >= $total),
            'logs' => $logs,
        ]);
    }

    private function phaseStep(?string $phase): int
    {
        return match ($phase) {
            'depensa' => 1,
            'adjudicator', 'reviewing' => 2,
            default => 0,
        };
    }

    /**
     * @return array{
     *     atake: array{true_positive:int,false_positive:int,true_negative:int,false_negative:int,unresolved:int},
     *     depensa: array{true_positive:int,false_positive:int,true_negative:int,false_negative:int,unresolved:int}
     * }
     */
    private function outcomeMatrix(Scan $scan): array
    {
        $matrix = [
            'atake' => AiEvaluationOutcome::emptyMatrix(),
            'depensa' => AiEvaluationOutcome::emptyMatrix(),
        ];
        $seen = [];

        $assessments = AiAssessment::query()
            ->whereIn('finding_id', $scan->findings()->select('id'))
            ->whereIn('reviewer', array_keys($matrix))
            ->with('finding:id,predicted_label')
            ->orderByDesc('completed_at')
            ->orderByDesc('id')
            ->get(['id', 'finding_id', 'reviewer', 'classification', 'completed_at']);

        foreach ($assessments as $assessment) {
            $key = $assessment->reviewer.':'.$assessment->finding_id;

            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;
            $outcome = AiEvaluationOutcome::classify(
                $assessment->finding?->predicted_label,
                $assessment->classification,
            );

            if ($assessment->reviewer === 'atake') {
                $matrix['atake'][$outcome]++;
            } elseif ($assessment->reviewer === 'depensa') {
                $matrix['depensa'][$outcome]++;
            }
        }

        return $matrix;
    }

    /**
     * Score each reviewer's latest result per finding against human ground truth.
     * Findings without a human label are kept separate from unresolved AI calls.
     *
     * @return array{
     *     atake: array{true_positive:int,false_positive:int,true_negative:int,false_negative:int,unresolved:int,awaiting_review:int},
     *     depensa: array{true_positive:int,false_positive:int,true_negative:int,false_negative:int,unresolved:int,awaiting_review:int}
     * }
     */
    private function humanOutcomeMatrix(Scan $scan): array
    {
        $matrix = [
            'atake' => AiEvaluationOutcome::emptyHumanMatrix(),
            'depensa' => AiEvaluationOutcome::emptyHumanMatrix(),
        ];
        $seen = [];

        $assessments = AiAssessment::query()
            ->whereIn('finding_id', $scan->findings()->select('id'))
            ->whereIn('reviewer', array_keys($matrix))
            ->with([
                'finding' => fn ($query) => $query
                    ->select(['id', 'final_label'])
                    ->with('feedback:id,finding_id,source'),
            ])
            ->orderByDesc('completed_at')
            ->orderByDesc('id')
            ->get(['id', 'finding_id', 'reviewer', 'classification', 'completed_at']);

        foreach ($assessments as $assessment) {
            $key = $assessment->reviewer.':'.$assessment->finding_id;

            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;
            $trustedFinalLabel = $assessment->finding?->feedback?->source === 'ai_pseudo'
                ? null
                : $assessment->finding?->final_label;

            if ($trustedFinalLabel === null) {
                if ($assessment->reviewer === 'atake') {
                    $matrix['atake']['awaiting_review']++;
                } elseif ($assessment->reviewer === 'depensa') {
                    $matrix['depensa']['awaiting_review']++;
                }

                continue;
            }

            $outcome = AiEvaluationOutcome::classifyAgainstHuman(
                $trustedFinalLabel,
                $assessment->classification,
            );

            if ($assessment->reviewer === 'atake') {
                $matrix['atake'][$outcome]++;
            } elseif ($assessment->reviewer === 'depensa') {
                $matrix['depensa'][$outcome]++;
            }
        }

        return $matrix;
    }

    private function outcomeAbbreviation(string $outcome): string
    {
        return match ($outcome) {
            'true_positive' => 'TP',
            'false_positive' => 'FP',
            'true_negative' => 'TN',
            'false_negative' => 'FN',
            default => '?',
        };
    }

    private function averageInferenceSeconds(Scan $scan): ?float
    {
        $durations = AiAssessment::query()
            ->whereIn('finding_id', $scan->findings()->select('id'))
            ->whereIn('reviewer', ['atake', 'depensa'])
            ->where(function ($query) {
                $query
                    ->where(fn ($review) => $review
                        ->where('reviewer', 'atake')
                        ->where('prompt_version', AtakeReviewer::PROMPT_VERSION))
                    ->orWhere(fn ($review) => $review
                        ->where('reviewer', 'depensa')
                        ->where('prompt_version', DepensaReviewer::PROMPT_VERSION));
            })
            ->whereNotNull('usage')
            ->latest('completed_at')
            ->limit(20)
            ->get(['usage'])
            ->map(fn (AiAssessment $assessment) => (float) data_get($assessment->usage, 'total_duration', 0) / 1_000_000_000)
            ->filter(fn (float $seconds) => $seconds > 0);

        return $durations->isEmpty() ? null : $durations->average();
    }

    /**
     * @return list<array{time: string|null, level: string, message: string, detail: string|null}>
     */
    private function recentAninoLogLines(Scan $scan, ?AninoAnalysisRun $run): array
    {
        $path = storage_path('logs/laravel.log');

        if (! File::exists($path)) {
            return [];
        }

        $lines = array_slice(file($path, FILE_IGNORE_NEW_LINES) ?: [], -1000);
        $entries = [];

        foreach ($lines as $line) {
            if (! str_contains($line, 'ANINO') || ! str_contains($line, '"scan_id":'.$scan->id)) {
                continue;
            }

            preg_match('/^\[(?<date>[^\]]+)\]\s+\w+\.(?<level>\w+):\s+(?<message>.*?)(?:\s+\{(?<json>.*)\})?$/', $line, $matches);

            if (
                isset($matches['date'])
                && $run?->started_at
                && $matches['date'] < $run->started_at->toDateTimeString()
            ) {
                continue;
            }

            $context = isset($matches['json'])
                ? json_decode('{'.$matches['json'].'}', true)
                : null;

            $entries[] = [
                'time' => isset($matches['date']) ? substr($matches['date'], 11, 8) : null,
                'level' => strtolower($matches['level'] ?? 'info'),
                'message' => $matches['message'] ?? 'ANINO log entry',
                'detail' => is_array($context) ? $this->formatAninoLogDetail($context) : null,
            ];
        }

        return array_slice(array_reverse($entries), 0, 12);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function formatAninoLogDetail(array $context): ?string
    {
        if (filled($context['error'] ?? null)) {
            return (string) $context['error'];
        }

        $details = array_filter([
            isset($context['reviewer']) ? strtoupper((string) $context['reviewer']) : null,
            isset($context['duration_seconds']) ? $context['duration_seconds'].'s' : null,
            isset($context['prompt_tokens']) ? $context['prompt_tokens'].' input tokens' : null,
            isset($context['output_tokens']) ? $context['output_tokens'].' output tokens' : null,
            isset($context['processed'], $context['total']) ? $context['processed'].'/'.$context['total'].' processed' : null,
        ]);

        return $details === [] ? null : implode(' | ', $details);
    }
}
