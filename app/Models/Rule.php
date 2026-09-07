<?php

namespace App\Models;

use Database\Factories\RuleFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Rule extends Model
{
    /** @use HasFactory<RuleFactory> */
    use HasFactory;

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

    /**
     * Mirrors Finding::rule() — joined on the scanner's native rule
     * identifier, not a numeric foreign key.
     *
     * @return HasMany<Finding, $this>
     */
    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class, 'rule_id', 'external_id');
    }

    /**
     * Recompute the rolling false-positive rate for this rule
     * based on confirmed triage feedback. Called after each
     * feedback submission and nightly via a scheduled job.
     */
    public function recalculateFpRate(): void
    {
        $trusted = $this->findings()
            ->whereNotNull('final_label')
            ->whereHas('feedback', fn ($query) => $query
                ->whereIn('source', ['human', 'benchmark', 'import'])
                ->where('training_eligible', true)
                ->whereColumn('triage_feedback.corrected_label', 'findings.final_label'));

        $total = (clone $trusted)->count();
        $fp = (clone $trusted)->where('final_label', 'false_positive')->count();

        $this->total_seen = $total;
        $this->total_false_positive = $fp;
        $this->historical_fp_rate = $total > 0 ? round($fp / $total, 4) : 0.0;
        $this->recommended_action = $this->resolveRecommendedAction($total);

        $this->save();
    }

    /**
     * Thresholds are checked highest-first — the previous order meant the
     * 'review_config' branch swallowed every rule and 'suppress' could
     * never be reached.
     *
     * @return 'suppress'|'review_config'|null
     */
    private function resolveRecommendedAction(int $totalTriaged): ?string
    {
        if ($totalTriaged < (int) config('sast.rules.min_samples', 20)) {
            return null;
        }

        return match (true) {
            $this->historical_fp_rate > (float) config('sast.rules.suppress_fp_rate', 0.85) => 'suppress',
            $this->historical_fp_rate > (float) config('sast.rules.review_fp_rate', 0.70) => 'review_config',
            default => null,
        };
    }
}
