<?php

namespace App\Services\AI;

/**
 * The JSON schema ATAKE and DEPENSA are both forced to reply in, passed
 * as Ollama's `format` param. One shared schema keeps the two reviewers'
 * output directly comparable for FindingAdjudicator, and keeps
 * ai_assessments rows uniform regardless of which reviewer wrote them.
 */
final class AiAssessmentSchema
{
    public static function make(): array
    {
        return [
            'type' => 'object',

            'properties' => [
                'classification' => [
                    'type' => 'string',

                    'enum' => [
                        'confirmed_tp',
                        'likely_tp',
                        'needs_validation',
                        'likely_fp',
                        'confirmed_fp',
                    ],
                ],

                'confidence' => [
                    'type' => 'number',
                    'minimum' => 0,
                    'maximum' => 1,
                ],

                'attacker_controlled' => [
                    'type' => ['boolean', 'null'],
                ],

                'sink_reachable' => [
                    'type' => ['boolean', 'null'],
                ],

                'mitigation_detected' => [
                    'type' => ['boolean', 'null'],
                ],

                'preconditions' => [
                    'type' => 'array',
                    'items' => [
                        'type' => 'string',
                    ],
                ],

                'supporting_evidence' => [
                    'type' => 'array',
                    'items' => [
                        'type' => 'string',
                    ],
                ],

                'contradicting_evidence' => [
                    'type' => 'array',
                    'items' => [
                        'type' => 'string',
                    ],
                ],

                'missing_evidence' => [
                    'type' => 'array',
                    'items' => [
                        'type' => 'string',
                    ],
                ],

                'remediation' => [
                    'type' => 'array',
                    'items' => [
                        'type' => 'string',
                    ],
                ],

                'reasoning_summary' => [
                    'type' => 'string',
                ],
            ],

            'required' => [
                'classification',
                'confidence',
                'attacker_controlled',
                'sink_reachable',
                'mitigation_detected',
                'preconditions',
                'supporting_evidence',
                'contradicting_evidence',
                'missing_evidence',
                'remediation',
                'reasoning_summary',
            ],
        ];
    }
}
