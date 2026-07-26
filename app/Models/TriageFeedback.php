<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

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

    public function finding()
    {
        return $this->belongsTo(Finding::class);
    }
}
