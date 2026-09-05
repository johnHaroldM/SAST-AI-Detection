<?php

namespace App\Console\Commands;

use App\Services\Scanner\ProjectScanner;
use App\Services\Scanner\SarifReportWriter;
use App\Services\ScannerReportParsers\NormalizedFindingDTO;
use Illuminate\Console\Command;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Standalone scan — no database, no project record, no queue.
 *
 * `sast:scan` is the integrated command: it creates a Scan row, ingests
 * findings and feeds the training loop. This one is the CI-shaped sibling.
 * It analyses a directory and prints SARIF, so it can run on a build agent
 * that has no access to the application database, with the report uploaded
 * afterwards through the normal ingestion endpoint.
 *
 *   php artisan sast:inspect . --format=sarif --output=results.sarif
 *   php artisan sast:inspect ./app --fail-on=HIGH
 */
class InspectPathCommand extends Command
{
    protected $signature = 'sast:inspect
        {path=. : Directory to analyse}
        {--format=table : table, sarif, or json}
        {--output= : Write the report to this file instead of stdout}
        {--fail-on= : Exit non-zero if a finding at this severity or above is present (LOW|MEDIUM|HIGH|CRITICAL)}
        {--quiet-summary : Suppress the human-readable summary on stderr}';

    protected $description = 'Analyse a directory and emit a report without touching the database';

    private const SEVERITY_ORDER = ['LOW' => 1, 'MEDIUM' => 2, 'HIGH' => 3, 'CRITICAL' => 4];

    public function handle(ProjectScanner $scanner, SarifReportWriter $writer): int
    {
        $path = realpath((string) $this->argument('path'));

        if ($path === false || ! is_dir($path)) {
            $this->error('Not a readable directory: '.$this->argument('path'));

            return self::FAILURE;
        }

        $started = microtime(true);
        $findings = $scanner->scan($path);
        $elapsed = round(microtime(true) - $started, 2);

        $rules = array_map(fn (string $rule) => app($rule), (array) config('sast.scanner.rules', []));

        $report = match ((string) $this->option('format')) {
            'sarif' => $writer->toJson($findings, $rules),
            'json' => $this->asJson($findings),
            default => null,
        };

        if ($report !== null) {
            $this->emit($report);
        } else {
            $this->renderTable($findings);
        }

        if (! $this->option('quiet-summary')) {
            $this->summarise($path, $findings, $scanner->filesScanned(), $elapsed);
        }

        return $this->exitCode($findings);
    }

    /**
     * @param  list<NormalizedFindingDTO>  $findings
     */
    private function asJson(array $findings): string
    {
        return json_encode(
            array_map(fn (NormalizedFindingDTO $f) => [
                'ruleId' => $f->ruleId,
                'cweId' => $f->cweId,
                'severity' => $f->severity,
                'file' => $f->filePath,
                'line' => $f->lineNumber,
                'message' => $f->message,
                'snippet' => $f->snippet,
            ], $findings),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );
    }

    private function emit(string $report): void
    {
        $destination = $this->option('output');

        if ($destination === null) {
            // Report to stdout so it can be piped; commentary goes to stderr.
            $this->output->writeln($report, OutputInterface::OUTPUT_RAW);

            return;
        }

        file_put_contents($destination, $report);
        $this->components->info('Report written to '.$destination);
    }

    /**
     * @param  list<NormalizedFindingDTO>  $findings
     */
    private function renderTable(array $findings): void
    {
        if ($findings === []) {
            return;
        }

        $this->table(
            ['Severity', 'Rule', 'Location', 'Message'],
            array_map(fn (NormalizedFindingDTO $f) => [
                $f->severity,
                str($f->ruleId)->afterLast('.')->toString(),
                $f->filePath.':'.$f->lineNumber,
                str($f->message)->limit(58)->toString(),
            ], array_slice($findings, 0, 100))
        );

        if (count($findings) > 100) {
            $this->line(sprintf('  …and %d more. Use --format=sarif for the full report.', count($findings) - 100));
        }
    }

    /**
     * @param  list<NormalizedFindingDTO>  $findings
     */
    private function summarise(string $path, array $findings, int $filesScanned, float $elapsed): void
    {
        $bySeverity = [];

        foreach ($findings as $finding) {
            $bySeverity[$finding->severity] = ($bySeverity[$finding->severity] ?? 0) + 1;
        }

        uksort($bySeverity, fn (string $a, string $b) => (self::SEVERITY_ORDER[$b] ?? 0) <=> (self::SEVERITY_ORDER[$a] ?? 0));

        $parts = [];

        foreach ($bySeverity as $severity => $count) {
            $parts[] = "{$count} {$severity}";
        }

        // stderr, so `--format=sarif > out.json` still produces clean SARIF.
        $this->errorOutput()->writeln(sprintf(
            "\n<options=bold>%d findings</> across %d files in %ss — %s\n<fg=gray>%s</>",
            count($findings),
            $filesScanned,
            $elapsed,
            $parts === [] ? 'clean' : implode(', ', $parts),
            $path,
        ));
    }

    /**
     * Commentary goes to stderr so a piped report stays machine-readable.
     * Falls back to normal output when stderr is not separately addressable
     * (as in the test runner's buffered output).
     */
    private function errorOutput(): OutputInterface
    {
        $underlying = $this->output->getOutput();

        return $underlying instanceof ConsoleOutputInterface
            ? $underlying->getErrorOutput()
            : $underlying;
    }

    /**
     * @param  list<NormalizedFindingDTO>  $findings
     */
    private function exitCode(array $findings): int
    {
        $threshold = strtoupper((string) $this->option('fail-on'));

        if ($threshold === '' || ! isset(self::SEVERITY_ORDER[$threshold])) {
            return self::SUCCESS;
        }

        foreach ($findings as $finding) {
            if ((self::SEVERITY_ORDER[$finding->severity] ?? 0) >= self::SEVERITY_ORDER[$threshold]) {
                $this->errorOutput()->writeln(
                    "<fg=red>Failing: at least one finding at or above {$threshold}.</>"
                );

                return self::FAILURE;
            }
        }

        return self::SUCCESS;
    }
}
