<?php

namespace App\Services\Scanner;

use App\Exceptions\LocalScanNotPermittedException;
use App\Jobs\ProcessScanJob;
use App\Models\Project;
use App\Models\Scan;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\Process\Process;

/**
 * Scan a project and have results ready to look at, in one call.
 *
 * The original flow assumed reports arrived from somewhere else — CI, a
 * scanner someone ran, a commit pushed to GitHub. That is the right model for
 * a hosted deployment, but it makes the common case ("look at this code now")
 * unnecessarily indirect. This runs the analyser, writes the SARIF artifact,
 * and drives ingestion inline so the caller lands on a finished scan.
 *
 * Ingestion is run inline rather than queued deliberately: a queued scan on a
 * machine with no worker running looks identical to a broken one.
 */
class OnDemandScanner
{
    public function __construct(
        private ProjectScanner $scanner,
        private SarifReportWriter $writer,
        private LocalScanGuard $guard,
    ) {}

    /**
     * @return array{scan: Scan, findings: int, files: int, seconds: float}
     *
     * @throws LocalScanNotPermittedException
     */
    public function scan(Project $project, ?string $path = null): array
    {
        $root = $this->guard->assertScannable($path ?? (string) $project->source_path);

        // A large monorepo can exceed the default web time limit, and this is
        // an explicit, user-initiated action rather than a stray request.
        $budget = (int) config('sast.scanner.local_scan.timeout_seconds', 300);
        set_time_limit($budget);

        $started = microtime(true);
        $findings = $this->scanner->scan($root);
        $filesScanned = $this->scanner->filesScanned();

        $rules = array_map(
            fn (string $rule) => app($rule),
            (array) config('sast.scanner.rules', [])
        );

        $reportPath = sprintf(
            'sast-reports/%d/ondemand-%s.sarif.json',
            $project->id,
            now()->format('Ymd-His-u')
        );

        Storage::put($reportPath, $this->writer->toJson($findings, $rules));

        $scan = Scan::create([
            'project_id' => $project->id,
            'source' => 'sarif',
            'commit_sha' => $this->resolveCommit($root),
            'branch' => $this->resolveBranch($root),
            'raw_report_path' => $reportPath,
            'status' => 'uploaded',
        ]);

        ProcessScanJob::dispatchSync($scan);

        return [
            'scan' => $scan->refresh(),
            'findings' => count($findings),
            'files' => $filesScanned,
            'seconds' => round(microtime(true) - $started, 1),
        ];
    }

    /**
     * Real HEAD when the directory is a git checkout, otherwise a stable
     * marker derived from the path — the scan is of a working tree, which may
     * legitimately have no commit at all.
     */
    private function resolveCommit(string $root): string
    {
        $head = $this->git($root, ['rev-parse', 'HEAD']);

        return preg_match('/^[0-9a-f]{40}$/i', $head) === 1
            ? strtolower($head)
            : substr(sha1($root), 0, 40);
    }

    private function resolveBranch(string $root): string
    {
        $branch = $this->git($root, ['rev-parse', '--abbrev-ref', 'HEAD']);

        return $branch !== '' && $branch !== 'HEAD' ? $branch : 'working-tree';
    }

    /**
     * @param  list<string>  $arguments
     */
    private function git(string $root, array $arguments): string
    {
        if (! is_dir($root.DIRECTORY_SEPARATOR.'.git')) {
            return '';
        }

        $process = new Process(['git', ...$arguments], $root, ['GIT_OPTIONAL_LOCKS' => '0']);
        $process->setTimeout(10);
        $process->run();

        return $process->isSuccessful() ? trim($process->getOutput()) : '';
    }
}
