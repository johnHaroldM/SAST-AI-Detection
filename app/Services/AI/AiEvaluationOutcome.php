<?php

namespace App\Services\AI;

final class AiEvaluationOutcome
{
    /**
     * Compare Rubix's prediction with an AI review of the underlying finding.
     *
     * @return 'true_positive'|'false_positive'|'true_negative'|'false_negative'|'unresolved'
     */
    public static function classify(?string $prediction, ?string $classification): string
    {
        $predictedPositive = match ($prediction) {
            'true_positive' => true,
            'false_positive' => false,
            default => null,
        };

        $actualPositive = match ($classification) {
            'confirmed_tp', 'likely_tp' => true,
            'confirmed_fp', 'likely_fp' => false,
            default => null,
        };

        if ($predictedPositive === null || $actualPositive === null) {
            return 'unresolved';
        }

        if ($predictedPositive) {
            return $actualPositive ? 'true_positive' : 'false_positive';
        }

        return $actualPositive ? 'false_negative' : 'true_negative';
    }

    /**
     * @return array{true_positive:int,false_positive:int,true_negative:int,false_negative:int,unresolved:int}
     */
    public static function emptyMatrix(): array
    {
        return [
            'true_positive' => 0,
            'false_positive' => 0,
            'true_negative' => 0,
            'false_negative' => 0,
            'unresolved' => 0,
        ];
    }
}
