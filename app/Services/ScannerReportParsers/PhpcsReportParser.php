<?php

namespace App\Services\ScannerReportParsers;

/** Parses PHP_CodeSniffer's `--report=json` output format. */
class PhpcsReportParser implements ScannerReportParser
{
    public function parse(string $rawContents): array
    {
        $data = json_decode($rawContents, true, flags: JSON_THROW_ON_ERROR);
        $findings = [];

        foreach ($data['files'] ?? [] as $filePath => $fileReport) {
            foreach ($fileReport['messages'] ?? [] as $message) {
                $findings[] = new NormalizedFindingDTO(
                    ruleId: $message['source'] ?? 'unknown',
                    cweId: null,
                    filePath: $filePath,
                    lineNumber: $message['line'] ?? 1,
                    severity: $message['type'] === 'ERROR' ? 'HIGH' : 'MEDIUM',
                    message: $message['message'] ?? '',
                    snippet: null,
                );
            }
        }

        return $findings;
    }
}
