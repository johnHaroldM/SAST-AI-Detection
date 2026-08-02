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
        'error' => 'HIGH',
        'warning' => 'MEDIUM',
        'note' => 'LOW',
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
                    cweId: $this->extractCwe($ruleMeta) ?? $this->propertyCwe($result),
                    filePath: $location['artifactLocation']['uri'] ?? 'unknown',
                    lineNumber: $location['region']['startLine'] ?? 1,
                    severity: $this->resolveSeverity($result),
                    message: $result['message']['text'] ?? '',
                    snippet: $location['region']['snippet']['text'] ?? null,
                );
            }
        }

        return $findings;
    }

    /**
     * SARIF's level vocabulary tops out at "error", so a CRITICAL finding
     * would be indistinguishable from a HIGH one after a round-trip. Writers
     * that care (including this app's own scanner) carry the original in
     * result properties, which is preferred when present and recognised.
     *
     * @param  array<string, mixed>  $result
     */
    private function resolveSeverity(array $result): string
    {
        $declared = strtoupper((string) ($result['properties']['severity'] ?? ''));

        if (in_array($declared, ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], true)) {
            return $declared;
        }

        return self::SEVERITY_MAP[$result['level'] ?? 'warning'] ?? 'MEDIUM';
    }

    /**
     * @param  array<string, mixed>  $result
     */
    private function propertyCwe(array $result): ?int
    {
        $cwe = $result['properties']['cweId'] ?? null;

        return is_numeric($cwe) ? (int) $cwe : null;
    }

    /**
     * @param  array<string, mixed>  $run
     * @return array<string, array<string, mixed>>
     */
    private function indexRules(array $run): array
    {
        $rules = $run['tool']['driver']['rules'] ?? [];

        return array_column($rules, null, 'id');
    }

    /**
     * @param  array<string, mixed>  $ruleMeta
     */
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
