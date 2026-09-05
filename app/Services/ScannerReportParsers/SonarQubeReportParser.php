<?php

namespace App\Services\ScannerReportParsers;

/** Parses SonarQube's issues export JSON format. */
class SonarQubeReportParser implements ScannerReportParser
{
    public function parse(string $rawContents): array
    {
        $data = json_decode($rawContents, true, flags: JSON_THROW_ON_ERROR);
        $findings = [];

        foreach ($data['issues'] ?? [] as $issue) {
            $findings[] = new NormalizedFindingDTO(
                ruleId: $issue['rule'] ?? 'unknown',
                cweId: null, // SonarQube exposes CWE via a separate security-standards lookup
                filePath: preg_replace('/^[^:]+:/', '', $issue['component'] ?? 'unknown'),
                lineNumber: $issue['line'] ?? 1,
                severity: strtoupper($issue['severity'] ?? 'MEDIUM'),
                message: $issue['message'] ?? '',
                snippet: null,
            );
        }

        return $findings;
    }
}
