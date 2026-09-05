<?php

namespace App\Http\Controllers\Web;

use App\Http\Controllers\Controller;
use App\Models\Finding;
use App\Models\Project;
use App\Services\RubixTriageService;
use App\Services\Triage\TriageGuidance;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

/**
 * A labelling queue that spans every scan, grouped by rule.
 *
 * The per-scan view answers "what is wrong with this commit". This answers a
 * different question — "give me the next thing to judge" — and the difference
 * matters for label quality: assessing twenty hardcoded-secret findings in a
 * row is faster and far more consistent than alternating between rule types,
 * because the reviewer holds one set of criteria in their head at a time.
 */
class TriageQueueController extends Controller
{
    private const PAGE_SIZE = 25;

    public function index(Request $request, RubixTriageService $triage, TriageGuidance $guidance): Response
    {
        $breakdown = $this->ruleBreakdown($request);
        $focusedRule = $this->focusedRule($request, $breakdown);

        $findings = Finding::query()
            ->with(['scan:id,project_id,branch', 'scan.project:id,name'])
            ->whereNull('final_label')
            ->when($focusedRule, fn ($query) => $query->where('rule_id', $focusedRule))
            ->when($request->integer('project'), fn ($query, $id) => $query->whereHas('scan', fn ($s) => $s->where('project_id', $id)))
            ->when($request->string('severity')->toString(), fn ($query, $severity) => $query->where('severity', $severity))
            // Stable ordering so paging never reshuffles a queue mid-review.
            ->orderBy('file_path')
            ->orderBy('line_number')
            ->orderBy('id')
            ->paginate(self::PAGE_SIZE)
            ->withQueryString();

        return Inertia::render('Triage/Queue', [
            'findings' => $findings,
            'breakdown' => $breakdown,
            'focusedRule' => $focusedRule,
            'projects' => Project::orderBy('name')->get(['id', 'name']),
            'readiness' => $triage->trainingReadiness(),
            'guidance' => $guidance->forMany(
                collect($findings->items())->pluck('cwe_id')->unique()
            ),
            'filters' => [
                'project' => $request->integer('project') ?: null,
                'severity' => $request->string('severity')->toString() ?: null,
            ],
        ]);
    }

    /**
     * Pending counts per rule, which drive both the sidebar and the default
     * focus. Ordered by volume so the biggest win is the first thing offered.
     *
     * @return list<array<string, mixed>>
     */
    private function ruleBreakdown(Request $request): array
    {
        $rows = Finding::query()
            ->whereNull('final_label')
            ->when($request->integer('project'), fn ($query, $id) => $query->whereHas('scan', fn ($s) => $s->where('project_id', $id)))
            ->selectRaw('rule_id, cwe_id, count(*) as pending')
            ->groupBy('rule_id', 'cwe_id')
            ->orderByDesc('pending')
            // Dropping to the query builder before fetching means these
            // aggregate rows arrive as plain objects instead of Finding
            // models carrying an alias no model declares.
            ->toBase()
            ->get()
            ->map(fn ($row) => [
                'rule_id' => (string) $row->rule_id,
                'cwe_id' => $row->cwe_id === null ? null : (int) $row->cwe_id,
                'pending' => (int) $row->pending,
            ]);

        return array_values($rows->all());
    }

    /**
     * @param  list<array<string, mixed>>  $breakdown
     */
    private function focusedRule(Request $request, array $breakdown): ?string
    {
        $requested = $request->string('rule')->toString();

        if ($requested !== '') {
            return $requested;
        }

        return $breakdown[0]['rule_id'] ?? null;
    }
}
