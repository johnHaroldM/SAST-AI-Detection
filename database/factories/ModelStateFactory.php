<?php

namespace Database\Factories;

use App\Models\ModelState;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ModelState>
 */
class ModelStateFactory extends Factory
{
    protected $model = ModelState::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'trained_at' => now(),
            'sample_size' => fake()->numberBetween(20, 500),
            'precision' => fake()->randomFloat(4, 0.5, 1),
            'recall' => fake()->randomFloat(4, 0.5, 1),
            'f1_score' => fake()->randomFloat(4, 0.5, 1),
            'confusion_matrix' => ['tp' => 40, 'fp' => 5, 'fn' => 6, 'tn' => 49],
            'deployment_status' => 'legacy',
            'decision_threshold' => null,
            'model_path' => null,
            'evaluation_metadata' => [],
        ];
    }
}
