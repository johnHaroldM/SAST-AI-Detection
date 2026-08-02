<?php

namespace App\Models;

use Database\Factories\FindingFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasOne;

class Finding extends Model
{
    /** @use HasFactory<FindingFactory> */
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
        'line_number' => 'integer',
    ];

    /**
     * @return BelongsTo<Scan, $this>
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    /**
     * findings.rule_id stores the scanner's *native* rule identifier
     * (e.g. "php.laravel.security.sql-injection"), not a numeric FK, so
     * this relation joins against rules.external_id. Getting this wrong
     * silently nulls out every rule lookup and freezes the
     * historical_fp_rate_rule feature at 0.0 for the whole dataset.
     */
    /**
     * @return BelongsTo<Rule, $this>
     */
    public function rule(): BelongsTo
    {
        return $this->belongsTo(Rule::class, 'rule_id', 'external_id');
    }

    /**
     * @return HasOne<TriageFeedback, $this>
     */
    public function feedback(): HasOne
    {
        return $this->hasOne(TriageFeedback::class);
    }

    public function isHighConfidenceTruePositive(float $threshold = 0.80): bool
    {
        return $this->predicted_label === 'true_positive'
            && $this->tp_probability >= $threshold;
    }
}
