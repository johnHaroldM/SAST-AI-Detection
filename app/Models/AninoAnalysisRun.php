<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AninoAnalysisRun extends Model
{
    protected $fillable = [
        'scan_id',
        'status',
        'phase',
        'current_finding_id',
        'candidate_finding_ids',
        'next_step',
        'total_findings',
        'processed_findings',
        'reviewed_findings',
        'failed_findings',
        'last_error',
        'started_at',
        'heartbeat_at',
        'phase_started_at',
        'completed_at',
    ];

    protected $casts = [
        'candidate_finding_ids' => 'array',
        'next_step' => 'integer',
        'total_findings' => 'integer',
        'processed_findings' => 'integer',
        'reviewed_findings' => 'integer',
        'failed_findings' => 'integer',
        'started_at' => 'datetime',
        'heartbeat_at' => 'datetime',
        'phase_started_at' => 'datetime',
        'completed_at' => 'datetime',
    ];

    /**
     * @return BelongsTo<Scan, $this>
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
