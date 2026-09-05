<?php

namespace App\Models;

use Database\Factories\ModelStateFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * Audit trail of each training run's held-out test performance, so the
 * dashboard can show a precision/recall trend line over time and catch
 * model drift or a bad retraining run before it ships to production.
 */
class ModelState extends Model
{
    /** @use HasFactory<ModelStateFactory> */
    use HasFactory;

    protected $fillable = [
        'trained_at', 'sample_size', 'precision', 'recall', 'f1_score', 'confusion_matrix',
    ];

    protected $casts = [
        'trained_at' => 'datetime',
        'precision' => 'float',
        'recall' => 'float',
        'f1_score' => 'float',
        'confusion_matrix' => 'array',
    ];
}
