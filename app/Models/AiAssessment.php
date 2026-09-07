<?php

namespace App\Models;

use App\Services\AI\AiEvaluationOutcome;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class AiAssessment extends Model
{
    protected $fillable = [
        'finding_id',
        'reviewer',          // atake | depensa | adjudicator
        'model',
        'model_version',
        'classification',    // confirmed_tp | likely_tp | needs_validation | likely_fp | confirmed_fp
        'evaluation_outcome', // Confusion-matrix outcome relative to Rubix's prediction
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
        'prompt_version',
        'context_hash',
        'usage',
        'raw_response',
        'completed_at',
    ];

    protected $casts = [
        'confidence' => 'float',
        'attacker_controlled' => 'boolean',
        'sink_reachable' => 'boolean',
        'mitigation_detected' => 'boolean',
        'preconditions' => 'array',
        'supporting_evidence' => 'array',
        'contradicting_evidence' => 'array',
        'missing_evidence' => 'array',
        'remediation' => 'array',
        'usage' => 'array',
        'raw_response' => 'array',
        'completed_at' => 'datetime',
    ];

    /**
     * @return BelongsTo<Finding, $this>
     */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }

    /**
     * @return HasMany<AiAssessmentFeedback, $this>
     */
    public function feedback(): HasMany
    {
        return $this->hasMany(AiAssessmentFeedback::class, 'assessment_id');
    }

    /**
     * Historical rows are classified on read; new rows persist the outcome.
     *
     * @return Attribute<string, never>
     */
    protected function evaluationOutcome(): Attribute
    {
        return Attribute::make(
            get: fn (mixed $value): string => is_string($value) && $value !== ''
                ? $value
                : AiEvaluationOutcome::classify(
                    $this->finding?->predicted_label,
                    $this->classification,
                ),
        );
    }
}
