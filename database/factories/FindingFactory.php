<?php

namespace Database\Factories;

use App\Models\Finding;
use App\Models\Rule;
use App\Models\Scan;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Finding>
 */
class FindingFactory extends Factory
{
    protected $model = Finding::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $severity = fake()->randomElement(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
        $cweId = fake()->randomElement([79, 89, 22, 78, 502]);

        return [
            'scan_id' => Scan::factory(),
            'rule_id' => 'php.laravel.security.'.fake()->slug(2),
            'cwe_id' => $cweId,
            'file_path' => 'app/Http/Controllers/'.fake()->word().'Controller.php',
            'line_number' => fake()->numberBetween(1, 400),
            'severity' => $severity,
            'message' => fake()->sentence(),
            'raw_snippet' => '$query = DB::raw($input);',
            'feature_vector' => null,
            'tp_probability' => null,
            'predicted_label' => null,
            'final_label' => null,
            'status' => 'pending',
        ];
    }

    /**
     * A finding carrying a complete feature vector — the state the ML
     * pipeline requires before a finding can be scored or trained on.
     */
    public function vectorized(): static
    {
        return $this->state(fn (array $attributes) => [
            'feature_vector' => [
                'cwe_id' => (int) ($attributes['cwe_id'] ?? 89),
                'scanner_severity' => $attributes['severity'] ?? 'HIGH',
                'file_extension' => 'php',
                'is_test_file' => 0,
                'cyclomatic_complexity' => fake()->numberBetween(1, 25),
                'has_sanitizer_in_ast' => fake()->randomElement([0, 1]),
                'line_depth_in_function' => fake()->numberBetween(0, 40),
                'historical_fp_rate_rule' => fake()->randomFloat(4, 0, 1),
                'developer_experience_lvl' => fake()->randomElement(['junior', 'mid', 'senior', 'unknown']),
            ],
        ]);
    }

    /**
     * A finding a human has confirmed — this is what train() consumes.
     */
    public function labeled(string $label): static
    {
        return $this->vectorized()->state([
            'final_label' => $label,
            'status' => 'triaged',
        ]);
    }

    public function scored(string $label = 'true_positive', float $probability = 0.9): static
    {
        return $this->vectorized()->state([
            'predicted_label' => $label,
            'tp_probability' => $probability,
        ]);
    }

    public function forRule(Rule $rule): static
    {
        return $this->state(['rule_id' => $rule->external_id]);
    }
}
