<?php

namespace App\Services\ScannerReportParsers;

/**
 * Resolves the correct normalizer for a given scanner's native output
 * format. Each parser converts its scanner-specific JSON/SARIF shape into
 * a common array of NormalizedFindingDTO so the rest of the pipeline
 * (FeatureVectorBuilder, RubixTriageService) never has to know which
 * scanner produced a finding.
 */
class ReportParserFactory
{
    public function make(string $source): ScannerReportParser
    {
        return match ($source) {
            'sarif'      => new SarifReportParser(),
            'semgrep'    => new SemgrepReportParser(),
            'sonarqube'  => new SonarQubeReportParser(),
            'bandit'     => new BanditReportParser(),
            'phpcs'      => new PhpcsReportParser(),
            default      => throw new \InvalidArgumentException("Unsupported scanner source: {$source}"),
        };
    }
}
