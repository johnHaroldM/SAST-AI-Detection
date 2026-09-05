<?php

namespace App\Console\Commands;

use App\Jobs\ProcessScanJob;
use App\Models\Project;
use App\Models\Scan;
use App\Services\Scanner\ProjectScanner;
use App\Services\Scanner\SarifReportWriter;
use App\Services\ScannerReportParsers\NormalizedFindingDTO;
use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\Process\Process;

/**
 * Runs the built-in scanner over a project and feeds the result through the
 * normal ingestion pipeline.
 *
 * The scanner writes SARIF rather than inserting findings directly, so a
 * locally scanned project takes exactly the same path as a report uploaded
 * from CI — one ingestion route, and a portable artifact left on disk.
 */
class ScanProjectCommand extends Command
{
    protected $signature = 'sast:scan
        {project? : Project ID or name; omit to scan every project with a source_path}
        {--path= : Scan this directory instead of the project source_path}
        {--branch=main : Branch label to record on the scan}
        {--sync : Process the scan inline instead of queueing it}
        {--dry-run : Report what would be found without persisting anything}';

    protected $description = 'Scan a project\'s source with the built-in analyser and ingest the findings';

    public function handle(ProjectScanner $scanner, SarifReportWriter $writer): int
    {
        $projects = $this->resolveProjects();

        if ($projects->isEmpty()) {
            $this->error('No project matched. Register one with a source_path, or pass --path.');

            return self::FAILURE;
        }

        $rules = array_map(fn (string $rule) => app($rule), (array) config('sast.scanner.rules', []));
        $grandTotal = 0;

        foreach ($projects as $project) {
            $root = $this->option('path') ?: $project->source_path;

            if (blank($root) || ! is_dir($root)) {
                $this->warn("  {$project->name}: no readable source_path, skipping");

                continue;
            }

            $this->line("Scanning <options=bold>{$project->name}</> — {$root}");

            $started = microtime(true);
            $findings = $scanner->scan($root);
            $elapsed = round(microtime(true) - $started, 1);

            $this->line(sprintf(
                '  %d findings across %d files (%d unparseable) in %ss',
                count($findings),
                $scanner->filesScanned(),
                count($scanner->skippedFiles()),
                $elapsed,
            ));

            $this->summariseByRule($findings);
            $grandTotal += count($findings);

            if ($this->option('dry-run')) {
                continue;
            }

            if ($findings === []) {
                $this->line('  nothing to ingest');

                continue;
            }

            $scan = $this->persist($project, $root, $writer->toJson($findings, $rules));

            if ($this->option('sync')) {
                ProcessScanJob::dispatchSync($scan);
                $this->info("  ingested as scan #{$scan->id} ({$scan->fresh()->status})");
            } else {
                ProcessScanJob::dispatch($scan);
                $this->info("  queued as scan #{$scan->id}");
            }
        }

        $this->newLine();
        $this->info("Total findings: {$grandTotal}");

        if (! $this->option('dry-run') && $grandTotal > 0) {
            $this->line('Next: triage them in the dashboard, then `php artisan sast:train --sync`.');
        }

        return self::SUCCESS;
    }

    /**
     * @return Collection<int, Project>
     */
    private function resolveProjects(): Collection
    {
        $identifier = $this->argument('project');

        if ($identifier === null) {
            return Project::query()->whereNotNull('source_path')->orderBy('name')->get();
        }

        return Project::query()
            ->where('id', is_numeric($identifier) ? $identifier : 0)
            ->orWhere('name', $identifier)
            ->get();
    }

    private function persist(Project $project, string $root, string $sarif): Scan
    {
        $path = sprintf('sast-reports/%d/native-%s.sarif.json', $project->id, now()->format('Ymd-His-u'));
        Storage::put($path, $sarif);

        return Scan::create([
            'project_id' => $project->id,
            'source' => 'sarif',
            'commit_sha' => $this->resolveCommit($root),
            'branch' => (string) $this->option('branch'),
            'raw_report_path' => $path,
            'status' => 'uploaded',
        ]);
    }

    /**
     * Real HEAD when the directory is a git checkout, otherwise a stable
     * synthetic marker so the fixed-width column stays valid.
     */
    private function resolveCommit(string $root): string
    {
        if (is_dir($root.'/.git')) {
            $process = new Process(['git', 'rev-parse', 'HEAD'], $root);
            $process->run();

            $head = trim($process->getOutput());

            if (preg_match('/^[0-9a-f]{40}$/i', $head)) {
                return strtolower($head);
            }
        }

        return substr(sha1($root), 0, 40);
    }

    /**
     * @param  list<NormalizedFindingDTO>  $findings
     */
    private function summariseByRule(array $findings): void
    {
        if ($findings === []) {
            return;
        }

        $counts = [];

        foreach ($findings as $finding) {
            $counts[$finding->ruleId] = ($counts[$finding->ruleId] ?? 0) + 1;
        }

        arsort($counts);

        foreach ($counts as $ruleId => $count) {
            $this->line(sprintf('    %-46s %d', $ruleId, $count));
        }
    }
}
