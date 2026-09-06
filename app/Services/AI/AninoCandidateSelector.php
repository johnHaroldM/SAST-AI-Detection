<?php

namespace App\Services\AI;

use App\Models\AninoAnalysisRun;
use App\Models\Finding;
use App\Models\Scan;
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
            ->where('scan_id', $scan->id)
            ->whereHas('aiContext')
            ->whereDoesntHave('aiAssessments', fn ($query) => $query->where('reviewer', 'adjudicator'))
            ->orderByRaw(
                "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
            )
            ->orderByDesc('tp_probability')
            ->orderBy('id')
            ->limit(max(1, $limit))
            ->pluck('id');
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
            ->where('scan_id', $run->scan_id)
            ->whereIn('id', $candidateIds)
            ->whereHas('aiContext')
            ->whereDoesntHave('aiAssessments', fn ($query) => $query
                ->where('reviewer', 'adjudicator')
                ->whereNotNull('completed_at'))
            ->pluck('id');

        return $candidateIds
            ->filter(fn (int $id) => $retryableIds->contains($id))
            ->values();
    }
}
