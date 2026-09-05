<?php

namespace App\Models;

use Database\Factories\ScanFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Scan extends Model
{
    /** @use HasFactory<ScanFactory> */
    use HasFactory;

    protected $fillable = [
        'project_id',
        'source',          // semgrep | sonarqube | bandit | phpcs | sarif
        'commit_sha',
        'branch',
        'raw_report_path', // path to stored original .json/.sarif
        'status',          // uploaded | parsing | scoring | complete | failed
        'total_findings',
        'suppressed_count',
    ];

    /**
     * @return BelongsTo<Project, $this>
     */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }

    /**
     * @return HasMany<Finding, $this>
     */
    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class);
    }
}
