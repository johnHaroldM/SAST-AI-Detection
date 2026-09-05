<?php

namespace App\Services\ScannerReportParsers;

/** Parses Bandit's (Python SAST) JSON output format. */
class BanditReportParser implements ScannerReportParser
{
    private const SEVERITY_MAP = ['LOW' => 'LOW', 'MEDIUM' => 'MEDIUM', 'HIGH' => 'HIGH'];

    public function parse(string $rawContents): array
    {
        $data = json_decode($rawContents, true, flags: JSON_THROW_ON_ERROR);
        $findings = [];

        foreach ($data['results'] ?? [] as $result) {
            $findings[] = new NormalizedFindingDTO(
                ruleId: $result['test_id'] ?? 'unknown',
                cweId: $result['issue_cwe']['id'] ?? null,
                filePath: $result['filename'] ?? 'unknown',
                lineNumber: $result['line_number'] ?? 1,
                severity: self::SEVERITY_MAP[strtoupper($result['issue_severity'] ?? 'MEDIUM')] ?? 'MEDIUM',
                message: $result['issue_text'] ?? '',
                snippet: $result['code'] ?? null,
            );
        }

        return $findings;
    }
}
