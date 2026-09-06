<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AiAssessment extends Model
{
    protected $fillable = [
        'finding_id',
        'reviewer',          // atake | depensa | adjudicator
        'model',
        'model_version',
        'classification',    // confirmed_tp | likely_tp | needs_validation | likely_fp | confirmed_fp
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
}
