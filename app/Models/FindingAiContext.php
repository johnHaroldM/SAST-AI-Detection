<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class FindingAiContext extends Model
{
    protected $fillable = [
        'finding_id',
        'source_commit',
        'context_hash',
        'metadata',
        'context',
    ];

    protected $casts = [
        'metadata' => 'array',
    ];

    /**
     * @return BelongsTo<Finding, $this>
     */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }
}
