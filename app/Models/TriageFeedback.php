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
        'notes',
    ];

    /**
     * @return BelongsTo<Finding, $this>
     */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }
}
