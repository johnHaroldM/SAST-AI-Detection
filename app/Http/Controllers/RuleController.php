<?php

namespace App\Http\Controllers;

use App\Models\Rule;
use Illuminate\Http\JsonResponse;

class RuleController extends Controller
{
    /**
     * GET /api/rules/noisy
     * The "Rule Noise & Recommendation" endpoint from the architecture
     * doc's capability matrix: surfaces scanner rules whose historical
     * false-positive rate crosses the review/suppress thresholds, so
     * a team can tune their SAST scanner config directly instead of
     * relying on the ML layer to keep filtering the same noise forever.
     */
    public function noisy(): JsonResponse
    {
        $rules = Rule::query()
            ->where('total_seen', '>=', 20)
            ->whereNotNull('recommended_action')
            ->orderByDesc('historical_fp_rate')
            ->get([
                'id', 'external_id', 'cwe_id', 'description',
                'total_seen', 'total_false_positive',
                'historical_fp_rate', 'recommended_action',
            ]);

        return response()->json([
            'count' => $rules->count(),
            'rules' => $rules,
        ]);
    }

    /**
     * GET /api/rules/{rule}/stats
     */
    public function show(Rule $rule): JsonResponse
    {
        return response()->json($rule);
    }
}
