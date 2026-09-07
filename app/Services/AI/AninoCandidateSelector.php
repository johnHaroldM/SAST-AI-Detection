<?php

namespace App\Services\AI;

use App\Models\AninoAnalysisRun;
use App\Models\Finding;
use App\Models\Scan;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Collection;

class AninoCandidateSelector
{
    /**
     * @return Collection<int, int>
     */
    public function forScan(Scan $scan, ?int $limit = null): Collection
    {
        $limit ??= max(1, (int) config('services.ollama.max_findings_per_run', 10));

        return Finding::query()
            ->join('finding_ai_contexts as current_context', 'current_context.finding_id', '=', 'findings.id')
            ->where('scan_id', $scan->id)
            // An assessment belongs to the exact evidence snapshot it saw.
            // When source becomes available (or otherwise changes), the old
            // adjudication remains useful history but must not prevent the
            // refreshed context from being reviewed.
            ->whereNotExists(fn (Builder $query) => $query
                ->selectRaw('1')
                ->from('ai_assessments')
                ->whereColumn('ai_assessments.finding_id', 'findings.id')
                ->whereColumn('ai_assessments.context_hash', 'current_context.context_hash')
                ->where('ai_assessments.reviewer', 'adjudicator')
                ->whereNotNull('ai_assessments.completed_at'))
            ->orderByRaw(
                "CASE findings.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
            )
            ->orderByDesc('findings.tp_probability')
            ->orderBy('findings.id')
            ->limit(max(1, $limit))
            ->pluck('findings.id');
    }

    /**
     * Return only candidates from an errored run that never reached adjudication.
     *
     * @return Collection<int, positive-int>
     */
    public function failedFromRun(AninoAnalysisRun $run): Collection
    {
        $candidateIds = collect($run->candidate_finding_ids ?? [])
            ->map(fn (mixed $id) => (int) $id)
            ->filter(fn (int $id) => $id > 0)
            ->values();

        if ($candidateIds->isEmpty()) {
            return collect();
        }

        $retryableIds = Finding::query()
            ->join('finding_ai_contexts as current_context', 'current_context.finding_id', '=', 'findings.id')
            ->where('scan_id', $run->scan_id)
            ->whereIn('findings.id', $candidateIds)
            ->whereNotExists(fn (Builder $query) => $query
                ->selectRaw('1')
                ->from('ai_assessments')
                ->whereColumn('ai_assessments.finding_id', 'findings.id')
                ->whereColumn('ai_assessments.context_hash', 'current_context.context_hash')
                ->where('ai_assessments.reviewer', 'adjudicator')
                ->whereNotNull('ai_assessments.completed_at'))
            ->pluck('findings.id');

        return $candidateIds
            ->filter(fn (int $id) => $retryableIds->contains($id))
            ->values();
    }
}
