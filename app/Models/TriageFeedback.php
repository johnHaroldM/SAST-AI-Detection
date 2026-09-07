<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class TriageFeedback extends Model
{
    protected $fillable = [
        'finding_id',
        'user_id',
        'original_prediction',  // what the model said
        'original_probability',
        'corrected_label',      // what the human confirmed
        'source',               // human | ai_pseudo | benchmark | import
        'source_ai_assessment_id',
        'training_eligible',    // false when an audit flags the label/evidence for re-review
        'training_exclusion_reason',
        'notes',
    ];

    protected $casts = [
        'training_eligible' => 'boolean',
    ];

    /**
     * @return BelongsTo<Finding, $this>
     */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }

    /**
     * The AI proposal that produced this weak label, when source=ai_pseudo.
     *
     * @return BelongsTo<AiAssessment, $this>
     */
    public function sourceAssessment(): BelongsTo
    {
        return $this->belongsTo(AiAssessment::class, 'source_ai_assessment_id');
    }
}
