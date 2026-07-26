<?php

namespace App\Services\ScannerReportParsers;

/**
 * Parses OASIS SARIF 2.1.0 reports (the format emitted by CodeQL, many
 * Semgrep configs, and most modern SAST tools when run with --sarif).
 * Serves as the reference implementation other scanner-specific parsers
 * (Semgrep native JSON, SonarQube, Bandit, PHPCS) follow the same shape.
 */
class SarifReportParser implements ScannerReportParser
{
    private const SEVERITY_MAP = [
        'error'   => 'HIGH',
        'warning' => 'MEDIUM',
        'note'    => 'LOW',
    ];

    public function parse(string $rawContents): array
    {
        $data = json_decode($rawContents, true, flags: JSON_THROW_ON_ERROR);

        $findings = [];

        foreach ($data['runs'] ?? [] as $run) {
            $rulesById = $this->indexRules($run);

            foreach ($run['results'] ?? [] as $result) {
                $location = $result['locations'][0]['physicalLocation'] ?? null;
                if ($location === null) {
                    continue; // skip results without a source location
                }

                $ruleId = $result['ruleId'] ?? 'unknown';
                $ruleMeta = $rulesById[$ruleId] ?? [];

                $findings[] = new NormalizedFindingDTO(
                    ruleId: $ruleId,
                    cweId: $this->extractCwe($ruleMeta),
                    filePath: $location['artifactLocation']['uri'] ?? 'unknown',
                    lineNumber: $location['region']['startLine'] ?? 1,
                    severity: self::SEVERITY_MAP[$result['level'] ?? 'warning'] ?? 'MEDIUM',
                    message: $result['message']['text'] ?? '',
                    snippet: $location['region']['snippet']['text'] ?? null,
                );
            }
        }

        return $findings;
    }

    private function indexRules(array $run): array
    {
        $rules = $run['tool']['driver']['rules'] ?? [];
        return array_column($rules, null, 'id');
    }

    private function extractCwe(array $ruleMeta): ?int
    {
        $tags = $ruleMeta['properties']['tags'] ?? [];

        foreach ($tags as $tag) {
            if (preg_match('/^CWE-(\d+)$/i', $tag, $m)) {
                return (int) $m[1];
            }
        }

        return null;
    }
}
