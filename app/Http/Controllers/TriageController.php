<?php

namespace App\Http\Controllers;

use App\Jobs\TrainSastModelJob;
use App\Models\Finding;
use App\Models\TriageFeedback;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule as ValidationRule;

class TriageController extends Controller
{
    // Retrain automatically once this many new confirmed labels accumulate
    // since the last training run, so the model keeps improving without
    // a human having to remember to kick off retraining manually.
    private const RETRAIN_BATCH_SIZE = 100;

    /**
     * POST /api/findings/{finding}/triage
     * Records a security engineer's confirm/override decision on a
     * finding's ML prediction. This is the core feedback-loop endpoint:
     * every call here writes a labeled training example for the next
     * model retraining pass.
     */
    public function store(Finding $finding, Request $request): JsonResponse
    {
        $validated = $request->validate([
            'corrected_label' => ['required', ValidationRule::in(['true_positive', 'false_positive'])],
            'notes'           => ['nullable', 'string', 'max:2000'],
        ]);

        DB::transaction(function () use ($finding, $validated, $request) {
            TriageFeedback::create([
                'finding_id'            => $finding->id,
                'user_id'               => $request->user()->id,
                'original_prediction'   => $finding->predicted_label,
                'original_probability'  => $finding->tp_probability,
                'corrected_label'       => $validated['corrected_label'],
                'notes'                 => $validated['notes'] ?? null,
            ]);

            $finding->final_label = $validated['corrected_label'];
            $finding->status = 'triaged';
            $finding->save();

            $finding->rule?->recalculateFpRate();
        });

        $this->maybeTriggerRetraining();

        return response()->json([
            'finding_id' => $finding->id,
            'final_label' => $finding->final_label,
            'status' => $finding->status,
        ]);
    }

    /**
     * POST /api/findings/bulk-triage
     * Accepts an array of {finding_id, corrected_label} pairs so a
     * reviewer can clear a whole page of the triage queue in one request
     * instead of one HTTP round-trip per finding.
     */
    public function bulkStore(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'decisions' => ['required', 'array', 'min:1', 'max:500'],
            'decisions.*.finding_id' => ['required', 'integer', 'exists:findings,id'],
            'decisions.*.corrected_label' => ['required', ValidationRule::in(['true_positive', 'false_positive'])],
        ]);

        $affectedRuleIds = [];

        DB::transaction(function () use ($validated, $request, &$affectedRuleIds) {
            $findings = Finding::whereIn('id', array_column($validated['decisions'], 'finding_id'))
                ->get()
                ->keyBy('id');

            foreach ($validated['decisions'] as $decision) {
                $finding = $findings->get($decision['finding_id']);
                if (!$finding) {
                    continue;
                }

                TriageFeedback::create([
                    'finding_id'           => $finding->id,
                    'user_id'              => $request->user()->id,
                    'original_prediction'  => $finding->predicted_label,
                    'original_probability' => $finding->tp_probability,
                    'corrected_label'      => $decision['corrected_label'],
                ]);

                $finding->final_label = $decision['corrected_label'];
                $finding->status = 'triaged';
                $finding->save();

                $affectedRuleIds[$finding->rule_id] = true;
            }
        });

        foreach (array_keys($affectedRuleIds) as $ruleId) {
            \App\Models\Rule::find($ruleId)?->recalculateFpRate();
        }

        $this->maybeTriggerRetraining();

        return response()->json(['updated' => count($validated['decisions'])]);
    }

    /**
     * Dispatch a background retraining job once enough new labeled
     * examples have accumulated. Cheap COUNT query gated behind a cache
     * lock so concurrent triage requests don't all trigger retraining.
     */
    private function maybeTriggerRetraining(): void
    {
        $newLabelsSinceLastTrain = Finding::whereNotNull('final_label')
            ->where('updated_at', '>=', now()->subDay())
            ->count();

        if ($newLabelsSinceLastTrain >= self::RETRAIN_BATCH_SIZE
            && cache()->add('sast:retrain-lock', true, now()->addMinutes(30))
        ) {
            TrainSastModelJob::dispatch()->onQueue('ml-training');
        }
    }
}
