<?php

namespace App\Services\AI;

use App\Models\AiAssessment;
use App\Models\Rule;
use App\Models\Scan;
use App\Models\TriageFeedback;
use Illuminate\Support\Facades\DB;

class AiTrainingPromoter
{
    /**
     * @return array{promoted:int,true_positive:int,false_positive:int,threshold:float}
     */
    public function promote(Scan $scan, int $userId): array
    {
        $threshold = $this->threshold();
        $promoted = 0;
        $truePositive = 0;
        $falsePositive = 0;
        $affectedRuleIds = [];

        DB::transaction(function () use ($scan, $userId, $threshold, &$promoted, &$truePositive, &$falsePositive, &$affectedRuleIds) {
            $assessments = AiAssessment::query()
                ->whereIn('finding_id', $scan->findings()->select('id'))
                ->where('reviewer', 'adjudicator')
                ->whereIn('classification', ['confirmed_tp', 'likely_tp', 'likely_fp', 'confirmed_fp'])
                ->where('confidence', '>=', $threshold)
                ->with('finding.feedback')
                ->get();

            foreach ($assessments as $assessment) {
                $finding = $assessment->finding;

                if (
                    ! $finding
                    || $finding->final_label !== null
                    || $finding->feedback !== null
                    || $finding->feature_vector === null
                ) {
                    continue;
                }

                $label = in_array($assessment->classification, ['confirmed_tp', 'likely_tp'], true)
                    ? 'true_positive'
                    : 'false_positive';

                TriageFeedback::create([
                    'finding_id' => $finding->id,
                    'user_id' => $userId,
                    'original_prediction' => $finding->predicted_label,
                    'original_probability' => $finding->tp_probability,
                    'corrected_label' => $label,
                    'source' => 'ai_pseudo',
                    'source_ai_assessment_id' => $assessment->id,
                    'notes' => sprintf(
                        'AI training label from ATAKE/DEPENSA adjudicator (%s, %.0f%% confidence).',
                        $assessment->classification,
                        (float) $assessment->confidence * 100
                    ),
                ]);

                $finding->final_label = $label;
                $finding->status = 'triaged';
                $finding->save();

                $affectedRuleIds[$finding->rule_id] = true;
                $promoted++;

                if ($label === 'true_positive') {
                    $truePositive++;
                } else {
                    $falsePositive++;
                }
            }
        });

        Rule::whereIn('external_id', array_keys($affectedRuleIds))
            ->get()
            ->each->recalculateFpRate();

        return [
            'promoted' => $promoted,
            'true_positive' => $truePositive,
            'false_positive' => $falsePositive,
            'threshold' => $threshold,
        ];
    }

    public function eligibleCount(Scan $scan): int
    {
        return AiAssessment::query()
            ->whereIn('finding_id', $scan->findings()->select('id'))
            ->where('reviewer', 'adjudicator')
            ->whereIn('classification', ['confirmed_tp', 'likely_tp', 'likely_fp', 'confirmed_fp'])
            ->where('confidence', '>=', $this->threshold())
            ->whereHas('finding', fn ($query) => $query
                ->whereNull('final_label')
                ->whereNotNull('feature_vector')
                ->whereDoesntHave('feedback'))
            ->count();
    }

    public function promotedCount(Scan $scan): int
    {
        return TriageFeedback::query()
            ->whereIn('finding_id', $scan->findings()->select('id'))
            ->where('source', 'ai_pseudo')
            ->count();
    }

    public function threshold(): float
    {
        return (float) config('sast.ai_training.confidence_threshold', 0.85);
    }
}
