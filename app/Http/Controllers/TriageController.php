<?php

namespace App\Http\Controllers;

use App\Jobs\TrainSastModelJob;
use App\Models\Finding;
use App\Models\ModelState;
use App\Models\Rule;
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
            'notes' => ['nullable', 'string', 'max:2000'],
        ]);

        DB::transaction(function () use (&$finding, $validated, $request) {
            $finding = Finding::query()->lockForUpdate()->findOrFail($finding->id);

            TriageFeedback::query()->updateOrCreate([
                'finding_id' => $finding->id,
            ], [
                'user_id' => $request->user()->id,
                'original_prediction' => $finding->predicted_label,
                'original_probability' => $finding->tp_probability,
                'corrected_label' => $validated['corrected_label'],
                'source' => 'human',
                'source_ai_assessment_id' => null,
                'training_eligible' => true,
                'training_exclusion_reason' => null,
                'notes' => $validated['notes'] ?? null,
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
     * DELETE /api/findings/{finding}/triage
     *
     * Retracts a decision. Labelling at speed means occasionally mislabelling,
     * and a wrong label is worse than no label — it teaches the classifier the
     * opposite of the truth. Removing the feedback row and recomputing the
     * rule's FP rate keeps the training set and the noise stats honest.
     */
    public function destroy(Finding $finding): JsonResponse
    {
        DB::transaction(function () use (&$finding) {
            $finding = Finding::query()->lockForUpdate()->findOrFail($finding->id);
            $finding->feedback()->delete();

            $finding->final_label = null;
            $finding->status = 'pending';
            $finding->save();

            $finding->rule?->recalculateFpRate();
        });

        return response()->json([
            'finding_id' => $finding->id,
            'final_label' => null,
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

        $decisionsByFinding = [];

        foreach ((array) $validated['decisions'] as $decision) {
            if (! is_array($decision)) {
                continue;
            }

            $findingId = $decision['finding_id'] ?? null;
            $correctedLabel = $decision['corrected_label'] ?? null;

            if (
                ! is_numeric($findingId)
                || ! is_string($correctedLabel)
                || ! in_array($correctedLabel, ['true_positive', 'false_positive'], true)
            ) {
                continue;
            }

            $decisionsByFinding[(int) $findingId] = [
                'finding_id' => (int) $findingId,
                'corrected_label' => $correctedLabel,
            ];
        }

        $decisions = array_values($decisionsByFinding);
        $affectedRuleIds = [];
        $updated = 0;

        DB::transaction(function () use ($decisions, $request, &$affectedRuleIds, &$updated) {
            $findings = Finding::query()
                ->whereIn('id', array_column($decisions, 'finding_id'))
                ->lockForUpdate()
                ->get()
                ->keyBy('id');

            foreach ($decisions as $decision) {
                $finding = $findings->get($decision['finding_id']);
                if (! $finding) {
                    continue;
                }

                TriageFeedback::query()->updateOrCreate([
                    'finding_id' => $finding->id,
                ], [
                    'user_id' => $request->user()->id,
                    'original_prediction' => $finding->predicted_label,
                    'original_probability' => $finding->tp_probability,
                    'corrected_label' => $decision['corrected_label'],
                    'source' => 'human',
                    'source_ai_assessment_id' => null,
                    'training_eligible' => true,
                    'training_exclusion_reason' => null,
                ]);

                $finding->final_label = $decision['corrected_label'];
                $finding->status = 'triaged';
                $finding->save();

                $affectedRuleIds[$finding->rule_id] = true;
                $updated++;
            }
        });

        // findings.rule_id holds the scanner's native rule identifier, so
        // these are looked up by external_id — Rule::find() would treat
        // them as primary keys and silently match nothing.
        Rule::whereIn('external_id', array_keys($affectedRuleIds))
            ->get()
            ->each->recalculateFpRate();

        $this->maybeTriggerRetraining();

        return response()->json(['updated' => $updated]);
    }

    /**
     * Dispatch a background retraining job once enough new labeled
     * examples have accumulated *since the last training run*. Cheap COUNT
     * query gated behind a cache lock so concurrent triage requests don't
     * all trigger retraining.
     *
     * Anchoring on the last ModelState matters: counting labels within a
     * rolling window instead means that once the threshold is crossed,
     * every subsequent triage re-triggers training for as long as the
     * window holds, regardless of how little new signal has arrived.
     */
    private function maybeTriggerRetraining(): void
    {
        $lastTrainedAt = ModelState::max('trained_at');

        $newLabels = Finding::query()
            ->whereNotNull('final_label')
            ->when($lastTrainedAt, fn ($query) => $query->where('updated_at', '>', $lastTrainedAt))
            ->count();

        if ($newLabels < $this->retrainBatchSize()) {
            return;
        }

        if (! cache()->add('sast:retrain-lock', true, now()->addMinutes(30))) {
            return;
        }

        TrainSastModelJob::dispatch()->onQueue('ml-training');
    }

    private function retrainBatchSize(): int
    {
        return max(1, (int) config('sast.training.retrain_batch_size', self::RETRAIN_BATCH_SIZE));
    }
}
