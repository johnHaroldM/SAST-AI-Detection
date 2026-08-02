<?php

namespace App\Services;

use App\Models\Finding;
use App\Models\Rule;

/**
 * Assembles the full associative feature vector for a Finding by combining:
 *  - static scanner metadata (severity, cwe_id, file_extension)
 *  - AST-derived code metrics (complexity, sanitizer presence, line depth)
 *  - historical rule performance (rolling false-positive rate)
 *  - contextual signals (test file, author experience)
 *
 * This is the single source of truth for what a "feature vector" is —
 * both training (RubixTriageService::train) and inference
 * (RubixTriageService::predictFinding) consume vectors built here.
 */
class FeatureVectorBuilder
{
    public function __construct(
        private AstFeatureExtractor $astExtractor,
        private GitBlameAuthorResolver $authorResolver,
    ) {}

    /**
     * Build and persist the feature_vector column for a single Finding.
     * $projectRoot is the absolute path to the checked-out repo so the
     * AST extractor can resolve $finding->file_path on disk.
     *
     * @return array<string, mixed>
     */
    public function build(Finding $finding, string $projectRoot): array
    {
        return $this->buildWithRule($finding, $projectRoot, $this->resolveRule($finding));
    }

    /**
     * Batch variant used by ProcessScanJob — resolves each distinct rule
     * once per scan instead of once per finding, which matters because a
     * single scan routinely produces hundreds of hits on the same rule.
     *
     * @param  iterable<Finding>  $findings
     */
    public function buildBatch(iterable $findings, string $projectRoot): void
    {
        $ruleCache = [];

        foreach ($findings as $finding) {
            $ruleCache[$finding->rule_id] ??= $this->resolveRule($finding);

            $this->buildWithRule($finding, $projectRoot, $ruleCache[$finding->rule_id]);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function buildWithRule(Finding $finding, string $projectRoot, Rule $rule): array
    {
        $absolutePath = rtrim($projectRoot, '/\\').DIRECTORY_SEPARATOR.ltrim($finding->file_path, '/\\');

        $astFeatures = $this->astExtractor->extract($absolutePath, $finding->line_number);
        $authorLevel = $this->authorResolver->resolve($absolutePath, $finding->line_number);

        $vector = [
            'cwe_id' => (int) $finding->cwe_id,
            'scanner_severity' => strtoupper((string) $finding->severity),
            'file_extension' => $astFeatures['file_extension'],
            'is_test_file' => $astFeatures['is_test_file'],
            'cyclomatic_complexity' => $astFeatures['cyclomatic_complexity'],
            'has_sanitizer_in_ast' => $astFeatures['has_sanitizer_in_ast'],
            'line_depth_in_function' => $astFeatures['line_depth_in_function'],
            'historical_fp_rate_rule' => (float) $rule->historical_fp_rate,
            'developer_experience_lvl' => $authorLevel,
        ];

        $finding->feature_vector = $vector;
        $finding->save();

        return $vector;
    }

    private function resolveRule(Finding $finding): Rule
    {
        return Rule::firstOrCreate(
            ['external_id' => $finding->rule_id],
            ['cwe_id' => $finding->cwe_id, 'historical_fp_rate' => 0.0]
        );
    }
}
