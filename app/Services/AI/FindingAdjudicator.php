<?php

namespace App\Services\AI;

use App\Models\AiAssessment;
use App\Models\Finding;

/**
 * Combines Rubix's tp_probability with ATAKE and DEPENSA's independent
 * opinions into a single system recommendation, stored as a third
 * AiAssessment row (reviewer = 'adjudicator').
 *
 * Deliberately deterministic, not a third LLM call — and deliberately
 * never returns confirmed_tp/confirmed_fp. Model agreement, however
 * strong, is not the same as confirmed evidence: a system recommendation
 * is the ceiling here. Only a human analyst action writes
 * findings.final_label — this class never touches it.
 *
 * The confidence formula is an explicit placeholder (see class docblock
 * below) — not a calibrated probability. Revisit once enough human
 * labels exist to evaluate Rubix-only vs Rubix+ATAKE vs
 * Rubix+ATAKE+DEPENSA against real outcomes.
 */
class FindingAdjudicator
{
    public const MODEL = 'deterministic-rules-v1';

    public const PROMPT_VERSION = 'rules-v1';

    public function update(Finding $finding): void
    {
        $contextHash = $finding->aiContext?->context_hash;
        $atake = $finding->aiAssessments()
            ->where('reviewer', 'atake')
            ->where('model', config('services.ollama.models.atake'))
            ->where('prompt_version', AtakeReviewer::PROMPT_VERSION)
            ->where('context_hash', $contextHash)
            ->latest('completed_at')
            ->first();
        $depensa = $finding->aiAssessments()
            ->where('reviewer', 'depensa')
            ->where('model', config('services.ollama.models.depensa'))
            ->where('prompt_version', DepensaReviewer::PROMPT_VERSION)
            ->where('context_hash', $contextHash)
            ->latest('completed_at')
            ->first();

        if (! $atake || ! $depensa) {
            return;
        }

        $classification = $this->classify($finding, $atake, $depensa);
        $confidence = $this->confidence($finding, $atake, $depensa, $classification);

        AiAssessment::query()->updateOrCreate(
            [
                'finding_id' => $finding->id,
                'reviewer' => 'adjudicator',
                'model' => self::MODEL,
                'prompt_version' => self::PROMPT_VERSION,
                'context_hash' => $contextHash,
            ],
            [
                'classification' => $classification,

                'evaluation_outcome' => AiEvaluationOutcome::classify(
                    $finding->predicted_label,
                    $classification,
                ),

                'confidence' => $confidence,

                'supporting_evidence' => [
                    sprintf('Rubix TP probability: %.3f', $finding->tp_probability ?? 0),
                    sprintf('ATAKE: %s (%.3f)', $atake->classification, $atake->confidence ?? 0),
                    sprintf('DEPENSA: %s (%.3f)', $depensa->classification, $depensa->confidence ?? 0),
                ],

                'contradicting_evidence' => [],

                'missing_evidence' => array_values(array_unique([
                    ...($atake->missing_evidence ?? []),
                    ...($depensa->missing_evidence ?? []),
                ])),

                'reasoning_summary' => 'Deterministic combination of Rubix, ATAKE, and DEPENSA outputs. '
                    .'Human triage remains authoritative.',

                'completed_at' => now(),
            ]
        );
    }

    /**
     * Only ever returns likely_tp, likely_fp, or needs_validation —
     * never a confirmed_* value. See class docblock: model agreement
     * alone is not grounds for a confirmed state.
     */
    private function classify(
        Finding $finding,
        AiAssessment $atake,
        AiAssessment $depensa
    ): string {
        $tp = ['confirmed_tp', 'likely_tp'];
        $fp = ['confirmed_fp', 'likely_fp'];

        if (
            in_array($atake->classification, $tp, true)
            && in_array($depensa->classification, $tp, true)
            && $finding->predicted_label === 'true_positive'
            && ($finding->tp_probability ?? 0) >= 0.75
        ) {
            return 'likely_tp';
        }

        if (
            in_array($atake->classification, $fp, true)
            && in_array($depensa->classification, $fp, true)
            && $finding->predicted_label === 'false_positive'
            && ($finding->tp_probability ?? 1) <= 0.25
        ) {
            return 'likely_fp';
        }

        return 'needs_validation';
    }

    private function confidence(
        Finding $finding,
        AiAssessment $atake,
        AiAssessment $depensa,
        string $classification,
    ): float {
        $tpProbability = (float) ($finding->tp_probability ?? 0.5);
        $ml = match (true) {
            in_array($classification, ['likely_tp', 'confirmed_tp'], true)
                && $finding->predicted_label === 'true_positive' => $tpProbability,
            in_array($classification, ['likely_fp', 'confirmed_fp'], true)
                && $finding->predicted_label === 'false_positive' => 1 - $tpProbability,
            default => 0.5,
        };
        $a = (float) ($atake->confidence ?? 0.5);
        $d = (float) ($depensa->confidence ?? 0.5);

        // This is only a starting heuristic — not a scientifically
        // calibrated probability. Calibrate with human-labeled data later.
        return round(
            min(1, max(0, ($ml * 0.40) + ($a * 0.30) + ($d * 0.30))),
            4
        );
    }
}
