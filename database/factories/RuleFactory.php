<?php

namespace Database\Factories;

use App\Models\Rule;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Rule>
 */
class RuleFactory extends Factory
{
    protected $model = Rule::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'external_id' => 'php.laravel.security.'.fake()->unique()->slug(2),
            'cwe_id' => fake()->randomElement([79, 89, 22, 78, 502]),
            'description' => fake()->sentence(),
            'total_seen' => 0,
            'total_false_positive' => 0,
            'historical_fp_rate' => 0.0,
            'recommended_action' => null,
        ];
    }
}
