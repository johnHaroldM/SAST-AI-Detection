<?php

namespace App\Services\ScannerReportParsers;

/**
 * Parses Semgrep's native `--json` output format (distinct from its
 * optional --sarif mode, which is handled by SarifReportParser).
 */
class SemgrepReportParser implements ScannerReportParser
{
    public function parse(string $rawContents): array
    {
        $data = json_decode($rawContents, true, flags: JSON_THROW_ON_ERROR);
        $findings = [];

        foreach ($data['results'] ?? [] as $result) {
            $findings[] = new NormalizedFindingDTO(
                ruleId: $result['check_id'] ?? 'unknown',
                cweId: $this->extractCwe($result['extra']['metadata']['cwe'] ?? null),
                filePath: $result['path'] ?? 'unknown',
                lineNumber: $result['start']['line'] ?? 1,
                severity: strtoupper($result['extra']['severity'] ?? 'MEDIUM'),
                message: $result['extra']['message'] ?? '',
                snippet: $result['extra']['lines'] ?? null,
            );
        }

        return $findings;
    }

    private function extractCwe(mixed $cwe): ?int
    {
        $value = is_array($cwe) ? ($cwe[0] ?? null) : $cwe;
        if ($value && preg_match('/CWE-(\d+)/i', (string) $value, $m)) {
            return (int) $m[1];
        }
        return null;
    }
}
