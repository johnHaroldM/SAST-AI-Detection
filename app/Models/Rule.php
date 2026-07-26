<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Rule extends Model
{
    protected $fillable = [
        'external_id',        // scanner's native rule ID, e.g. "php.laravel.security.sql-injection"
        'cwe_id',
        'description',
        'total_seen',
        'total_false_positive',
        'historical_fp_rate',
        'recommended_action',  // null | 'suppress' | 'downgrade_severity' | 'review_config'
    ];

    protected $casts = [
        'historical_fp_rate' => 'float',
    ];

    public function findings()
    {
        return $this->hasMany(Finding::class);
    }

    /**
     * Recompute the rolling false-positive rate for this rule
     * based on confirmed triage feedback. Called after each
     * feedback submission and nightly via a scheduled job.
     */
    public function recalculateFpRate(): void
    {
        $total = $this->findings()->whereNotNull('final_label')->count();
        $fp = $this->findings()->where('final_label', 'false_positive')->count();

        $this->total_seen = $total;
        $this->total_false_positive = $fp;
        $this->historical_fp_rate = $total > 0 ? round($fp / $total, 4) : 0.0;

        if ($this->historical_fp_rate > 0.70 && $total >= 20) {
            $this->recommended_action = 'review_config';
        } elseif ($this->historical_fp_rate > 0.85 && $total >= 20) {
            $this->recommended_action = 'suppress';
        } else {
            $this->recommended_action = null;
        }

        $this->save();
    }
}
