<?php

namespace App\Http\Controllers\Web;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreScanRequest;
use App\Jobs\AnalyzeFindingsWithAninoJob;
use App\Jobs\TrainSastModelJob;
use App\Models\AninoAnalysisRun;
use App\Models\Project;
use App\Models\Scan;
use App\Services\AI\AiEvaluationOutcome;
use App\Services\AI\AiTrainingPromoter;
use App\Services\AI\AninoCandidateSelector;
use App\Services\AI\AninoRunManager;
use App\Services\AI\FindingContextBuilder;
use App\Services\ScanIngestionService;
use App\Services\Triage\TriageGuidance;
use App\Services\Workspaces\SourceWorkspaceFactory;
use Illuminate\Http\RedirectResponse;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Renders the Inertia pages for the scans list and individual scan triage
 * view. Deliberately thin — all the real logic (filtering, pagination,
 * count aggregates) already lives on ScanController and is reused here
 * rather than duplicated, since the JSON API and the dashboard serve the
 * same data shape.
 */
class ScanDashboardController extends Controller
{
    public function index(): Response
    {
        $scans = Scan::query()
            ->withCount([
                'findings',
                'findings as true_positive_count' => fn ($q) => $q
                    ->where('predicted_label', 'true_positive'),
                'findings as false_positive_count' => fn ($q) => $q
                    ->where('predicted_label', 'false_positive'),
                'findings as pending_triage_count' => fn ($q) => $q
                    ->where('status', 'pending'),
            ])
            ->latest()
            ->paginate(25);

        return Inertia::render('Scans/Index', [
            'scans' => $scans,
        ]);
    }

    public function create(): Response
    {
        return Inertia::render('Scans/Upload', [
            'projects' => Project::orderBy('name')
                ->get(['id', 'name']),
        ]);
    }

    /**
     * Inertia counterpart to ScanController::store(). The SPA needs a
     * redirect-with-flash response here, not the 202 JSON the API returns,
     * so the two share validation + dispatch through StoreScanRequest and
     * ScanIngestionService instead of one calling the other.
     */
    public function store(
        StoreScanRequest $request,
        ScanIngestionService $ingestion,
    ): RedirectResponse {
        $scan = $ingestion->ingest(
            $request->validated(),
            $request->file('report'),
        );

        return to_route('scans.show', $scan)
            ->with(
                'success',
                'Report uploaded — parsing and scoring have been queued.',
            );
    }

    public function show(
        Scan $scan,
        TriageGuidance $guidance,
    ): Response {
        $userId = (int) auth()->id();

        $scan->loadCount([
            'findings',

            'findings as true_positive_count' => fn ($q) => $q
                ->where('predicted_label', 'true_positive'),

            'findings as false_positive_count' => fn ($q) => $q
                ->where('predicted_label', 'false_positive'),

            'findings as pending_triage_count' => fn ($q) => $q
                ->where('status', 'pending'),

            'findings as ai_context_count' => fn ($q) => $q
                ->whereHas('aiContext'),

            'findings as ai_reviewed_count' => fn ($q) => $q
                ->whereHas(
                    'aiAssessments',
                    fn ($assessment) => $assessment
                        ->where('reviewer', 'adjudicator'),
                ),
        ]);

        $findings = $scan->findings()
            ->with([
                'rule',

                'feedback:id,finding_id,source',

                'aiAssessments' => fn ($query) => $query
                    ->with([
                        'feedback' => fn ($feedback) => $feedback
                            ->where('user_id', $userId),
                    ])
                    ->orderByRaw(
                        "CASE reviewer
                            WHEN 'adjudicator' THEN 0
                            WHEN 'atake' THEN 1
                            WHEN 'depensa' THEN 2
                            ELSE 3
                        END"
                    )
                    ->orderByDesc('completed_at')
                    ->orderByDesc('id'),
            ])
            ->orderByDesc('tp_probability')
            ->paginate(100);

        $findings->getCollection()->each(function ($finding) {
            $trustedFinalLabel = $finding->feedback?->source === 'ai_pseudo'
                ? null
                : $finding->final_label;

            $latestAssessments = $finding->aiAssessments
                ->unique('reviewer')
                ->values();

            $latestAssessments->each(
                function ($assessment) use (
                    $finding,
                    $trustedFinalLabel,
                ) {
                    $assessment->setAttribute(
                        'evaluation_outcome',
                        AiEvaluationOutcome::classify(
                            $finding->predicted_label,
                            $assessment->classification,
                        ),
                    );

                    $assessment->setAttribute(
                        'human_evaluation_outcome',
                        AiEvaluationOutcome::classifyAgainstHuman(
                            $trustedFinalLabel,
                            $assessment->classification,
                        ),
                    );
                }
            );

            $finding->setAttribute(
                'trusted_final_label',
                $trustedFinalLabel,
            );

            $finding->unsetRelation('feedback');

            $finding->setRelation(
                'aiAssessments',
                $latestAssessments,
            );
        });

        return Inertia::render('Scans/Show', [
            'scan' => $scan,
            'findings' => $findings,

            'anino' => [
                'enabled' => (bool) config(
                    'services.ollama.enabled'
                ),
                'atake_model' => config(
                    'services.ollama.models.atake'
                ),
                'depensa_model' => config(
                    'services.ollama.models.depensa'
                ),
                'queue' => config(
                    'services.ollama.queue',
                    'ai-analysis',
                ),
            ],

            'guidance' => $guidance->forMany(
                collect($findings->items())
                    ->pluck('cwe_id')
                    ->unique(),
            ),
        ]);
    }

    public function analyzeWithAnino(
        Scan $scan,
        SourceWorkspaceFactory $workspaces,
        FindingContextBuilder $aiContextBuilder,
        AninoCandidateSelector $aninoCandidates,
        AninoRunManager $runManager,
    ): RedirectResponse {
        if (! config('services.ollama.enabled')) {
            return back()->with(
                'error',
                'ATAKE/DEPENSA is disabled. Set ANINO_AI_ENABLED=true and restart the app.',
            );
        }

        if ($runManager->active($scan) !== null) {
            return back()->with(
                'error',
                'ATAKE/DEPENSA is already reviewing this scan. Watch the progress panel for the current run.',
            );
        }

        $workspace = $workspaces->for($scan);

        try {
            $scan->findings()
                ->with('aiContext')
                ->chunkById(
                    100,
                    function ($findings) use (
                        $aiContextBuilder,
                        $scan,
                        $workspace,
                    ) {
                        foreach ($findings as $finding) {
                            $currentContext = $finding->aiContext;

                            $currentVersion = data_get(
                                $currentContext?->metadata,
                                'format_version',
                            );

                            if (
                                $currentContext
                                && (
                                    $currentVersion
                                        === FindingContextBuilder::FORMAT_VERSION
                                    || ! $workspace->isAvailable()
                                )
                            ) {
                                continue;
                            }

                            $snapshot = $aiContextBuilder->build(
                                $finding,
                                $workspace->path(),
                            );

                            $finding->aiContext()->updateOrCreate(
                                [],
                                [
                                    'source_commit' => $scan->commit_sha,
                                    'context_hash' => $snapshot['hash'],
                                    'metadata' => $snapshot['metadata'],
                                    'context' => $snapshot['context'],
                                ],
                            );
                        }
                    }
                );
        } finally {
            $workspace->release();
        }

        /*
         * A retry is determined by the previous run's terminal state,
         * not by whether failedFromRun() happens to return a non-empty
         * collection.
         *
         * Without this distinction an errored run with no remaining
         * retryable findings would incorrectly fall back to forScan()
         * and start a new full/high-risk review.
         */
        $previousRun = $scan->aninoAnalysisRuns()
            ->latest('id')
            ->first();

        $isRetryRun = $previousRun !== null
            && in_array(
                $previousRun->status,
                [
                    'failed',
                    'complete_with_errors',
                ],
                true,
            );

        $candidateIds = $isRetryRun
            ? $aninoCandidates
                ->failedFromRun($previousRun)
                ->values()
                ->all()
            : $aninoCandidates
                ->forScan($scan)
                ->values()
                ->all();

        $runTarget = count($candidateIds);

        if ($candidateIds === []) {
            return back()->with(
                'error',
                $isRetryRun
                    ? 'No failed ATAKE/DEPENSA findings remain to retry.'
                    : 'No findings are available for ATAKE/DEPENSA review yet.',
            );
        }

        $run = AninoAnalysisRun::query()->create([
            'scan_id' => $scan->id,
            'status' => 'queued',
            'phase' => 'queued',
            'candidate_finding_ids' => $candidateIds,
            'next_step' => 0,
            'total_findings' => $runTarget,
            'processed_findings' => 0,
            'reviewed_findings' => 0,
            'failed_findings' => 0,
            'heartbeat_at' => now(),
        ]);

        AnalyzeFindingsWithAninoJob::dispatch(
            $scan->id,
            $run->id,
            0,
        )->onQueue(
            config(
                'services.ollama.queue',
                'ai-analysis',
            )
        );

        $findingLabel = $runTarget === 1
            ? 'finding'
            : 'findings';

        $message = $isRetryRun
            ? "ATAKE and DEPENSA retry queued for {$runTarget} failed {$findingLabel}."
            : "ATAKE and DEPENSA review queued for {$runTarget} high-risk {$findingLabel}.";

        return back()->with(
            'success',
            $message,
        );
    }

    public function trainFromAnino(
        Scan $scan,
        AiTrainingPromoter $trainingPromoter,
    ): RedirectResponse {
        $result = $trainingPromoter->promote(
            $scan,
            (int) auth()->id(),
        );

        if ($result['promoted'] === 0) {
            return back()->with(
                'error',
                'No high-confidence ATAKE/DEPENSA adjudications are ready for Rubix training yet.',
            );
        }

        TrainSastModelJob::dispatch()
            ->onQueue('ml-training');

        return back()->with(
            'success',
            "Promoted {$result['promoted']} AI labels and queued Rubix retraining.",
        );
    }
}
