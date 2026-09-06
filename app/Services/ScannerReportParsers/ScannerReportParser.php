<?php

namespace App\Services\ScannerReportParsers;

interface ScannerReportParser
{
    /**
     * @param  string  $rawContents  raw JSON/SARIF file contents
     * @return NormalizedFindingDTO[]
     */
    public function parse(string $rawContents): array;
}
