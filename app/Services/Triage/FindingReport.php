<?php

namespace App\Services\Triage;

use App\Models\AiAssessment;
use App\Models\Finding;
use App\Services\AI\AiEvaluationOutcome;
use App\Services\Workspaces\SourceWorkspaceFactory;

/**
 * Assembles the full explanation of a single finding: what the vulnerability
 * is, why this particular code was flagged, and how to change it — with the
 * developer's own source in front of them rather than a textbook example.
 *
 * The code snapshot is read through the workspace layer, so it works the same
 * for a local checkout and for a hosted deployment that clones per scan.
 */
class FindingReport
{
    private const CONTEXT_LINES = 8;

    public function __construct(
        private TriageGuidance $guidance,
        private SuggestedFix $suggestedFix,
        private SourceWorkspaceFactory $workspaces,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function for(Finding $finding): array
    {
        $advice = $this->guidance->for($finding->cwe_id);

        return [
            'finding' => [
                'id' => $finding->id,
                'rule_id' => $finding->rule_id,
                'cwe_id' => $finding->cwe_id,
                'severity' => $finding->severity,
                'message' => $finding->message,
                'file_path' => $finding->file_path,
                'line_number' => $finding->line_number,
                'status' => $finding->status,
                'final_label' => $finding->final_label,
                'tp_probability' => $finding->tp_probability,
                'predicted_label' => $finding->predicted_label,
                'scan_id' => $finding->scan_id,
                'project' => $finding->scan?->project?->name,
                'branch' => $finding->scan?->branch,
            ],

            // What this class of vulnerability is, and what an attacker gains.
            'what' => [
                'title' => $advice['title'],
                'risk' => $advice['risk'],
                'reference' => $advice['reference'],
            ],

            // Why this specific code tripped the rule, and how to tell whether
            // it is real — the same criteria used when labelling.
            'why' => [
                'detected' => $finding->message,
                'truePositive' => $advice['truePositive'],
                'falsePositive' => $advice['falsePositive'],
                'reviewerNote' => $finding->feedback?->notes,
            ],

            // How to fix it: the general remedy plus a rewrite of this line.
            'how' => [
                'summary' => $advice['fix'],
                'suggestion' => $this->suggestedFix->for($finding),
                'generic' => [
                    'vulnerable' => $advice['vulnerable'],
                    'secure' => $advice['secure'],
                ],
            ],

            'location' => $this->location($finding),
            'code' => $this->codeSnapshot($finding),
            'aiReview' => $this->aiReview($finding),
        ];
    }

    /**
     * @return array{
     *     rubix_prediction:string|null,
     *     rubix_probability:float|null,
     *     reviewers:list<array<string, mixed>>
     * }
     */
    private function aiReview(Finding $finding): array
    {
        $assessments = $finding->aiAssessments()
            ->whereIn('reviewer', ['atake', 'depensa'])
            ->orderByDesc('completed_at')
            ->orderByDesc('id')
            ->get();
        $reviewers = [];

        foreach (['atake', 'depensa'] as $reviewer) {
            $assessment = $assessments->first(
                fn (AiAssessment $candidate) => $candidate->reviewer === $reviewer
            );

            if ($assessment === null) {
                $reviewers[] = [
                    'reviewer' => $reviewer,
                    'available' => false,
                    'model' => (string) config("services.ollama.models.{$reviewer}"),
                ];

                continue;
            }

            $outcome = AiEvaluationOutcome::classify(
                $finding->predicted_label,
                $assessment->classification,
            );

            $reviewers[] = [
                'reviewer' => $reviewer,
                'available' => true,
                'model' => $assessment->model,
                'classification' => $assessment->classification,
                'evaluation_outcome' => $outcome,
                'outcome_reason' => $this->outcomeReason(
                    $reviewer,
                    $finding->predicted_label,
                    $outcome,
                ),
                'confidence' => $assessment->confidence,
                'attacker_controlled' => $assessment->attacker_controlled,
                'sink_reachable' => $assessment->sink_reachable,
                'mitigation_detected' => $assessment->mitigation_detected,
                'reasoning_summary' => $assessment->reasoning_summary,
                'preconditions' => array_values($assessment->preconditions ?? []),
                'supporting_evidence' => array_values($assessment->supporting_evidence ?? []),
                'contradicting_evidence' => array_values($assessment->contradicting_evidence ?? []),
                'missing_evidence' => array_values($assessment->missing_evidence ?? []),
                'remediation' => array_values($assessment->remediation ?? []),
                'completed_at' => $assessment->completed_at?->toDateTimeString(),
            ];
        }

        return [
            'rubix_prediction' => $finding->predicted_label,
            'rubix_probability' => $finding->tp_probability,
            'reviewers' => $reviewers,
        ];
    }

    private function outcomeReason(string $reviewer, ?string $prediction, string $outcome): string
    {
        $name = strtoupper($reviewer);

        if ($prediction === null) {
            return "Rubix has no prediction yet, so {$name}'s verdict cannot be scored against it.";
        }

        return match ($outcome) {
            'true_positive' => "Rubix predicted a vulnerability, and {$name} found evidence that supports it.",
            'false_positive' => "Rubix predicted a vulnerability, but {$name} judged it to be a false alarm.",
            'true_negative' => "Rubix predicted a false alarm, and {$name} agreed that it is not a supported vulnerability.",
            'false_negative' => "Rubix predicted a false alarm, but {$name} found evidence of a vulnerability.",
            default => "{$name} needs more evidence before it can confirm or reject Rubix's prediction.",
        };
    }

    /**
     * Where this finding physically lives. With fourteen projects registered,
     * "app/Http/Controllers/FormController.php" alone is ambiguous — several
     * of them have a file at exactly that path.
     *
     * @return array{project:string|null, root:string|null, absolute:string|null, directory:string, file:string, segments:list<string>}
     */
    private function location(Finding $finding): array
    {
        $project = $finding->scan?->project;
        $root = $project?->source_path ? rtrim($project->source_path, '/\\') : null;

        $relative = str_replace('\\', '/', $finding->file_path);
        $segments = array_values(array_filter(explode('/', $relative), fn (string $s) => $s !== ''));
        $file = array_pop($segments) ?? $relative;

        return [
            'project' => $project?->name,
            'root' => $root,
            'absolute' => $root === null ? null : $root.DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $relative),
            'directory' => implode('/', $segments),
            'file' => $file,
            'segments' => $segments,
        ];
    }

    /**
     * The real lines around the finding, so the report shows the code being
     * discussed rather than a paraphrase of it.
     *
     * @return array{available:bool, reason:string|null, lines:list<array{number:int, text:string, flagged:bool}>}
     */
    private function codeSnapshot(Finding $finding): array
    {
        $scan = $finding->scan;

        if ($scan === null) {
            return $this->unavailable('finding is not attached to a scan');
        }

        $workspace = $this->workspaces->for($scan);

        try {
            if (! $workspace->isAvailable()) {
                return $this->unavailable('no source workspace is available for this project');
            }

            $absolute = rtrim($workspace->path(), '/\\')
                .DIRECTORY_SEPARATOR
                .ltrim($finding->file_path, '/\\');

            if (! is_file($absolute) || ! is_readable($absolute)) {
                return $this->unavailable('file is not present in the workspace');
            }

            $lines = file($absolute, FILE_IGNORE_NEW_LINES);

            if ($lines === false) {
                return $this->unavailable('file could not be read');
            }

            $start = max(0, $finding->line_number - 1 - self::CONTEXT_LINES);
            $end = min(count($lines) - 1, $finding->line_number - 1 + self::CONTEXT_LINES);

            $snapshot = [];

            for ($i = $start; $i <= $end; $i++) {
                $snapshot[] = [
                    'number' => $i + 1,
                    'text' => $lines[$i],
                    'flagged' => $i === $finding->line_number - 1,
                ];
            }

            return ['available' => true, 'reason' => null, 'lines' => $snapshot];
        } finally {
            // A git-cloned workspace must not survive rendering one report.
            $workspace->release();
        }
    }

    /**
     * @return array{available:bool, reason:string, lines:list<array{number:int, text:string, flagged:bool}>}
     */
    private function unavailable(string $reason): array
    {
        return ['available' => false, 'reason' => $reason, 'lines' => []];
    }
}
