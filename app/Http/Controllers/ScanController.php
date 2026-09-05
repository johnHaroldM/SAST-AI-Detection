<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreScanRequest;
use App\Models\Scan;
use App\Services\ScanIngestionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

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
}
