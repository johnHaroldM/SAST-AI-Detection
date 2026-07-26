<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Project extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'vcs_repo_slug',
        'vcs_access_token',
    ];

    public function scans()
    {
        return $this->hasMany(Scan::class);
    }
}
