<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Finding extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_id',
        'rule_id',
        'cwe_id',
        'file_path',
        'line_number',
        'severity',
        'message',
        'raw_snippet',
        'feature_vector',   // JSON-encoded feature array used for prediction
        'tp_probability',   // 0.0 - 1.0 score returned by Rubix ML
        'predicted_label',  // 'true_positive' | 'false_positive'
        'final_label',      // human-confirmed label (nullable until triaged)
        'status',           // pending | triaged | suppressed | reported
    ];

    protected $casts = [
        'feature_vector' => 'array',
        'tp_probability' => 'float',
        'line_number'    => 'integer',
    ];

    public function scan()
    {
        return $this->belongsTo(Scan::class);
    }

    public function rule()
    {
        return $this->belongsTo(Rule::class);
    }

    public function feedback()
    {
        return $this->hasOne(TriageFeedback::class);
    }

    public function isHighConfidenceTruePositive(float $threshold = 0.80): bool
    {
        return $this->predicted_label === 'true_positive'
            && $this->tp_probability >= $threshold;
    }
}
