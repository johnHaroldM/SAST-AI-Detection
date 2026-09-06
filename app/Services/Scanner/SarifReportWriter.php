<?php

namespace App\Services\Scanner;

use App\Services\ScannerReportParsers\NormalizedFindingDTO;

/**
 * Serialises findings to SARIF 2.1.0.
 *
 * The built-in scanner writes its results as SARIF rather than pushing DTOs
 * straight into the database, so there is exactly one ingestion path in the
 * system regardless of whether a scan came from here, Semgrep, or CodeQL.
 * It also means every scan leaves a portable artifact on disk.
 */
class SarifReportWriter
{
    private const LEVEL_BY_SEVERITY = [
        'CRITICAL' => 'error',
        'HIGH' => 'error',
        'MEDIUM' => 'warning',
        'LOW' => 'note',
    ];

    /**
     * @param  list<NormalizedFindingDTO>  $findings
     * @param  iterable<SecurityRule>  $rules
     */
    public function toJson(array $findings, iterable $rules): string
    {
        return json_encode(
            $this->toArray($findings, $rules),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );
    }

    /**
     * @param  list<NormalizedFindingDTO>  $findings
     * @param  iterable<SecurityRule>  $rules
     * @return array<string, mixed>
     */
    public function toArray(array $findings, iterable $rules): array
    {
        return [
            'version' => '2.1.0',
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'runs' => [[
                'tool' => ['driver' => [
                    'name' => 'sast-ai-detection built-in scanner',
                    'informationUri' => 'https://github.com/',
                    'rules' => $this->describeRules($rules),
                ]],
                'results' => array_map($this->describeFinding(...), $findings),
            ]],
        ];
    }

    /**
     * @param  iterable<SecurityRule>  $rules
     * @return list<array<string, mixed>>
     */
    private function describeRules(iterable $rules): array
    {
        $described = [];

        foreach ($rules as $rule) {
            $tags = ['security'];

            if ($rule->cweId() !== null) {
                $tags[] = 'CWE-'.$rule->cweId();
            }

            $described[] = [
                'id' => $rule->id(),
                'shortDescription' => ['text' => $rule->description()],
                'defaultConfiguration' => ['level' => $this->levelFor($rule->severity())],
                'properties' => ['tags' => $tags],
            ];
        }

        return $described;
    }

    /**
     * @return array<string, mixed>
     */
    private function describeFinding(NormalizedFindingDTO $finding): array
    {
        $region = ['startLine' => $finding->lineNumber];

        if ($finding->snippet !== null) {
            $region['snippet'] = ['text' => $finding->snippet];
        }

        return [
            'ruleId' => $finding->ruleId,
            'level' => $this->levelFor($finding->severity),
            'message' => ['text' => $finding->message],
            'locations' => [[
                'physicalLocation' => [
                    'artifactLocation' => ['uri' => $finding->filePath],
                    'region' => $region,
                ],
            ]],
            // SARIF's level vocabulary has no CRITICAL, so it would collapse
            // to HIGH on the round-trip through the parser. Carrying the
            // original in properties keeps the distinction without leaving
            // valid SARIF.
            'properties' => [
                'severity' => strtoupper($finding->severity),
                'cweId' => $finding->cweId,
            ],
        ];
    }

    private function levelFor(string $severity): string
    {
        return self::LEVEL_BY_SEVERITY[strtoupper($severity)] ?? 'warning';
    }
}
