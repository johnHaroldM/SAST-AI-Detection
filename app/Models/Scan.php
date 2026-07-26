<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Scan extends Model
{
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

    public function findings()
    {
        return $this->hasMany(Finding::class);
    }
}
