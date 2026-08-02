<?php

namespace Database\Seeders;

use App\Models\Finding;
use App\Models\Project;
use App\Models\Rule;
use App\Models\Scan;
use Illuminate\Database\Seeder;

/**
 * Seeds a labeled findings set large enough to train the first model.
 *
 * The app cannot score anything until a model exists, and a model cannot be
 * trained until a human has labeled enough findings — so a brand new install
 * has no way to see the ML half of the system working. This seeder produces
 * a realistic, learnable dataset to break that deadlock during development.
 *
 * Labels follow a deliberate signal rather than coin flips: findings that are
 * sanitized, shallow, in test files, or attached to historically noisy rules
 * skew false positive; deep, complex, unsanitized findings on clean rules
 * skew true positive. Roughly 12% of rows contradict that pattern so the
 * classifier has to generalize instead of memorizing a rule.
 *
 * Run with: php artisan db:seed --class=SastDemoSeeder
 */
class SastDemoSeeder extends Seeder
{
    private const FINDINGS_PER_SCAN = 40;

    private const SCANS = 4;

    /** @var list<array{external_id:string, cwe_id:int, noisy:bool, description:string}> */
    private const RULES = [
        ['external_id' => 'php.laravel.security.sql-injection', 'cwe_id' => 89, 'noisy' => false, 'description' => 'Raw SQL built from request input'],
        ['external_id' => 'php.laravel.security.xss-blade-raw', 'cwe_id' => 79, 'noisy' => true, 'description' => 'Unescaped Blade output'],
        ['external_id' => 'php.security.path-traversal', 'cwe_id' => 22, 'noisy' => false, 'description' => 'File path built from user input'],
        ['external_id' => 'php.security.command-injection', 'cwe_id' => 78, 'noisy' => false, 'description' => 'Shell command built from user input'],
        ['external_id' => 'php.security.unserialize-user-input', 'cwe_id' => 502, 'noisy' => true, 'description' => 'unserialize() on untrusted data'],
        ['external_id' => 'php.laravel.mass-assignment', 'cwe_id' => 915, 'noisy' => true, 'description' => 'Model filled directly from request'],
    ];

    public function run(): void
    {
        $project = Project::firstOrCreate(
            ['name' => 'Demo Monorepo'],
            ['vcs_repo_slug' => 'acme/demo-monorepo']
        );

        $rules = collect(self::RULES)->map(fn (array $rule) => Rule::updateOrCreate(
            ['external_id' => $rule['external_id']],
            ['cwe_id' => $rule['cwe_id'], 'description' => $rule['description']],
        ));

        $noisyIds = array_values(collect(self::RULES)->where('noisy', true)->pluck('external_id')->all());

        for ($s = 1; $s <= self::SCANS; $s++) {
            $scan = Scan::create([
                'project_id' => $project->id,
                'source' => 'sarif',
                'commit_sha' => bin2hex(random_bytes(20)),
                'branch' => $s === self::SCANS ? 'feature/checkout-rewrite' : 'main',
                'raw_report_path' => "sast-reports/{$project->id}/demo-scan-{$s}.json",
                'status' => 'complete',
                'total_findings' => self::FINDINGS_PER_SCAN,
            ]);

            for ($i = 0; $i < self::FINDINGS_PER_SCAN; $i++) {
                $this->createFinding($scan, fake()->randomElement(self::RULES), $noisyIds);
            }
        }

        $rules->each->recalculateFpRate();

        $labeled = Finding::whereNotNull('final_label')->count();

        $this->command->info("Seeded {$labeled} labeled findings across ".self::SCANS.' scans.');
        $this->command->info('Next: php artisan sast:train --sync');
    }

    /**
     * @param  array{external_id:string, cwe_id:int, noisy:bool, description:string}  $rule
     * @param  list<string>  $noisyIds
     */
    private function createFinding(Scan $scan, array $rule, array $noisyIds): void
    {
        $isTestFile = fake()->boolean(20);
        $hasSanitizer = fake()->boolean($rule['noisy'] ? 70 : 30);
        $complexity = fake()->numberBetween(1, 30);
        $lineDepth = fake()->numberBetween(0, 60);
        $severity = fake()->randomElement(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
        $experience = fake()->randomElement(['junior', 'mid', 'senior', 'unknown']);
        $ruleFpRate = in_array($rule['external_id'], $noisyIds, true)
            ? fake()->randomFloat(4, 0.6, 0.95)
            : fake()->randomFloat(4, 0.0, 0.35);

        // Weighted signal the classifier can learn, then flipped ~12% of the
        // time so the data isn't perfectly separable.
        $falsePositiveScore = ($hasSanitizer ? 2 : 0)
            + ($isTestFile ? 2 : 0)
            + ($ruleFpRate > 0.5 ? 2 : 0)
            + ($complexity < 8 ? 1 : 0)
            + ($lineDepth < 10 ? 1 : 0)
            + (in_array($severity, ['LOW', 'MEDIUM'], true) ? 1 : 0);

        $label = $falsePositiveScore >= 4 ? 'false_positive' : 'true_positive';

        if (fake()->boolean(12)) {
            $label = $label === 'false_positive' ? 'true_positive' : 'false_positive';
        }

        $directory = $isTestFile ? 'tests/Feature' : 'app/Http/Controllers';
        $lineNumber = fake()->numberBetween(10, 400);

        Finding::create([
            'scan_id' => $scan->id,
            'rule_id' => $rule['external_id'],
            'cwe_id' => $rule['cwe_id'],
            'file_path' => $directory.'/'.fake()->word().'Controller.php',
            'line_number' => $lineNumber,
            'severity' => $severity,
            'message' => $rule['description'].' at line '.$lineNumber,
            'raw_snippet' => '$result = DB::select("SELECT * FROM orders WHERE id = ".$request->id);',
            'feature_vector' => [
                'cwe_id' => $rule['cwe_id'],
                'scanner_severity' => $severity,
                'file_extension' => 'php',
                'is_test_file' => $isTestFile ? 1 : 0,
                'cyclomatic_complexity' => $complexity,
                'has_sanitizer_in_ast' => $hasSanitizer ? 1 : 0,
                'line_depth_in_function' => $lineDepth,
                'historical_fp_rate_rule' => $ruleFpRate,
                'developer_experience_lvl' => $experience,
            ],
            'final_label' => $label,
            'status' => 'triaged',
        ]);
    }
}
