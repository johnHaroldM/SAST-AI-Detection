<?php

namespace App\Http\Controllers\Web;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreScanRequest;
use App\Models\Project;
use App\Models\Scan;
use App\Services\ScanIngestionService;
use App\Services\Triage\TriageGuidance;
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
                'findings as true_positive_count' => fn ($q) => $q->where('predicted_label', 'true_positive'),
                'findings as false_positive_count' => fn ($q) => $q->where('predicted_label', 'false_positive'),
                'findings as pending_triage_count' => fn ($q) => $q->where('status', 'pending'),
            ])
            ->latest()
            ->paginate(25);

        return Inertia::render('Scans/Index', ['scans' => $scans]);
    }

    public function create(): Response
    {
        return Inertia::render('Scans/Upload', [
            'projects' => Project::orderBy('name')->get(['id', 'name']),
        ]);
    }

    /**
     * Inertia counterpart to ScanController::store(). The SPA needs a
     * redirect-with-flash response here, not the 202 JSON the API returns,
     * so the two share validation + dispatch through StoreScanRequest and
     * ScanIngestionService instead of one calling the other.
     */
    public function store(StoreScanRequest $request, ScanIngestionService $ingestion): RedirectResponse
    {
        $scan = $ingestion->ingest($request->validated(), $request->file('report'));

        return to_route('scans.show', $scan)
            ->with('success', 'Report uploaded — parsing and scoring have been queued.');
    }

    public function show(Scan $scan, TriageGuidance $guidance): Response
    {
        $scan->loadCount([
            'findings',
            'findings as true_positive_count' => fn ($q) => $q->where('predicted_label', 'true_positive'),
            'findings as false_positive_count' => fn ($q) => $q->where('predicted_label', 'false_positive'),
            'findings as pending_triage_count' => fn ($q) => $q->where('status', 'pending'),
        ]);

        $findings = $scan->findings()
            ->with('rule')
            ->orderByDesc('tp_probability')
            ->paginate(100);

        return Inertia::render('Scans/Show', [
            'scan' => $scan,
            'findings' => $findings,
            // Impact and remediation for each CWE on this page, so a reviewer
            // can act on a finding without leaving it to look up what it means.
            'guidance' => $guidance->forMany(
                collect($findings->items())->pluck('cwe_id')->unique()
            ),
        ]);
    }
}
