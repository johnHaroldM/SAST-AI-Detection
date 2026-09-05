<?php

namespace Database\Factories;

use App\Models\Project;
use App\Models\Scan;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Scan>
 */
class ScanFactory extends Factory
{
    protected $model = Scan::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'project_id' => Project::factory(),
            'source' => 'sarif',
            'commit_sha' => fake()->regexify('[0-9a-f]{40}'),
            'branch' => 'main',
            'raw_report_path' => 'sast-reports/1/'.fake()->uuid().'.json',
            'status' => 'uploaded',
            'total_findings' => 0,
            'suppressed_count' => 0,
        ];
    }

    public function complete(): static
    {
        return $this->state(['status' => 'complete']);
    }
}
