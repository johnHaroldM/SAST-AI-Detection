<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AiAssessmentFeedback extends Model
{
    /** @var list<string> */
    public const VERDICTS = [
        'correct',
        'incorrect',
        'partially_correct',
        'insufficient_context',
    ];

    /** @var list<string> */
    public const CLASSIFICATIONS = [
        'confirmed_tp',
        'likely_tp',
        'needs_validation',
        'likely_fp',
        'confirmed_fp',
    ];

    /** @var list<string> */
    public const REASON_CODES = [
        'missed_source',
        'missed_sink',
        'missed_sanitizer',
        'incorrect_data_flow',
        'incorrect_precondition',
        'hallucinated_evidence',
        'missing_context',
        'weak_reasoning',
        'other',
    ];

    protected $table = 'ai_assessment_feedback';

    protected $fillable = [
        'assessment_id',
        'user_id',
        'verdict',
        'corrected_classification',
        'reason_codes',
        'notes',
        'reviewed_at',
    ];

    protected $casts = [
        'reason_codes' => 'array',
        'reviewed_at' => 'datetime',
    ];

    /**
     * @return BelongsTo<AiAssessment, $this>
     */
    public function assessment(): BelongsTo
    {
        return $this->belongsTo(AiAssessment::class, 'assessment_id');
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
