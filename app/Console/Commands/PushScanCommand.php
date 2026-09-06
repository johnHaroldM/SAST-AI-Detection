<?php

namespace App\Console\Commands;

use App\Services\Scanner\ProjectScanner;
use App\Services\Scanner\SarifReportWriter;
use App\Services\ScannerReportParsers\NormalizedFindingDTO;
use Illuminate\Console\Command;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Symfony\Component\Process\Process;

/**
 * Scan a directory and upload the report to a Signal/Bench installation.
 *
 * Runs anywhere PHP does — PowerShell, bash, a CI container — and needs no
 * database access, because it authenticates with a per-project ingest token
 * and talks to the stateless ingest endpoint.
 *
 * On what leaves the machine: SARIF embeds one line of source per finding.
 * That is what makes a report reviewable, and it is also source code crossing
 * a network boundary. The command says so before uploading, and --no-snippets
 * strips them for code you are not permitted to transmit.
 */
class PushScanCommand extends Command
{
    protected $signature = 'sast:push
        {path=. : Directory to scan}
        {--endpoint= : Base URL of the installation, e.g. https://sast.example.com}
        {--token= : Project ingest token; prefer the SAST_INGEST_TOKEN environment variable}
        {--branch= : Branch label; detected from git when omitted}
        {--commit= : Commit SHA; detected from git when omitted}
        {--no-snippets : Strip source snippets from the report before uploading}
        {--dry-run : Scan and summarise without uploading anything}
        {--yes : Skip the confirmation prompt (for CI)}';

    protected $description = 'Scan a directory and upload the findings to a Signal/Bench installation';

    public function handle(ProjectScanner $scanner, SarifReportWriter $writer): int
    {
        $path = realpath((string) $this->argument('path'));

        if ($path === false || ! is_dir($path)) {
            $this->error('Not a readable directory: '.$this->argument('path'));

            return self::FAILURE;
        }

        $token = (string) ($this->option('token') ?: config('sast.cli.ingest_token', ''));
        $endpoint = rtrim((string) ($this->option('endpoint') ?: config('sast.cli.endpoint', '')), '/');

        if ($this->option('token')) {
            // argv is visible to every other process on the box, and is
            // recorded in shell history and CI logs. Saying so is worth more
            // than refusing, since refusing just gets worked around.
            $this->warn('  Token passed as an argument — it will be recorded in shell history and CI logs.');
            $this->line('  <fg=gray>Prefer the SAST_INGEST_TOKEN environment variable.</>');
        }

        if (! $this->option('dry-run') && ($token === '' || $endpoint === '')) {
            $this->error('An endpoint and an ingest token are required to upload.');
            $this->line('  Set SAST_ENDPOINT and SAST_INGEST_TOKEN, or pass --endpoint and --token.');
            $this->line('  Generate a token on the project\'s page in the dashboard.');

            return self::FAILURE;
        }

        $this->line("Scanning <options=bold>{$path}</>");
        $findings = $scanner->scan($path);

        $this->line(sprintf(
            '  %d findings across %d files',
            count($findings),
            $scanner->filesScanned(),
        ));

        if ($findings === []) {
            $this->info('Nothing to upload.');

            return self::SUCCESS;
        }

        if ($this->option('no-snippets')) {
            $findings = $this->stripSnippets($findings);
        }

        $rules = array_map(fn (string $rule) => app($rule), (array) config('sast.scanner.rules', []));
        $sarif = $writer->toJson($findings, $rules);

        if ($this->option('dry-run')) {
            $this->info('Dry run — nothing was uploaded.');

            return self::SUCCESS;
        }

        if (! $this->confirmUpload($endpoint, count($findings))) {
            $this->warn('Cancelled.');

            return self::SUCCESS;
        }

        return $this->upload($endpoint, $token, $sarif, $path);
    }

    /**
     * Uploading source is a decision, not a side effect — so it is stated
     * plainly and confirmed, unless explicitly waived for CI.
     */
    private function confirmUpload(string $endpoint, int $findings): bool
    {
        $carriesSource = ! $this->option('no-snippets');

        $this->newLine();
        $this->line('  About to upload to <options=bold>'.$endpoint.'</>');
        $this->line("  {$findings} findings, including file paths and line numbers.");

        if ($carriesSource) {
            $this->line('  <fg=yellow>One line of source code per finding is included.</>');
            $this->line('  <fg=gray>Use --no-snippets if you are not permitted to transmit this code.</>');
        } else {
            $this->line('  <fg=gray>Source snippets stripped.</>');
        }

        $this->newLine();

        return $this->option('yes') || $this->confirm('Upload?', false);
    }

    private function upload(string $endpoint, string $token, string $sarif, string $path): int
    {
        try {
            // The SARIF is already in memory — writing it to a temp file only
            // to read it straight back would leave the report sitting on disk
            // in a world-readable location for no benefit.
            $response = Http::withToken($token)
                ->timeout(120)
                ->attach('report', $sarif, 'report.sarif.json')
                ->post($endpoint.'/api/ingest/scans', [
                    'source' => 'sarif',
                    'commit_sha' => $this->resolveCommit($path),
                    'branch' => $this->resolveBranch($path),
                ]);
        } catch (ConnectionException $e) {
            $this->error('Could not reach '.$endpoint);
            $this->line('  '.$e->getMessage());

            return self::FAILURE;
        }

        if ($response->status() === 401) {
            $this->error('Rejected: the ingest token is invalid or has been revoked.');

            return self::FAILURE;
        }

        if ($response->failed()) {
            $this->error('Upload failed with HTTP '.$response->status());
            $this->line('  '.str($response->body())->limit(300));

            return self::FAILURE;
        }

        $body = $response->json();

        $this->newLine();
        $this->info(sprintf(
            'Uploaded to %s as scan #%s.',
            $body['project'] ?? 'the project',
            $body['scan_id'] ?? '?',
        ));
        $this->line('  Triage it at '.$this->argument('path'));

        return self::SUCCESS;
    }

    /**
     * @param  list<NormalizedFindingDTO>  $findings
     * @return list<NormalizedFindingDTO>
     */
    private function stripSnippets(array $findings): array
    {
        $this->line('  <fg=gray>Stripping source snippets before upload.</>');

        return array_map(fn (NormalizedFindingDTO $f) => new NormalizedFindingDTO(
            ruleId: $f->ruleId,
            cweId: $f->cweId,
            filePath: $f->filePath,
            lineNumber: $f->lineNumber,
            severity: $f->severity,
            message: $f->message,
            snippet: null,
        ), $findings);
    }

    private function resolveCommit(string $path): string
    {
        $override = (string) $this->option('commit');

        if (preg_match('/^[0-9a-f]{40}$/i', $override) === 1) {
            return strtolower($override);
        }

        $head = $this->git($path, ['rev-parse', 'HEAD']);

        return preg_match('/^[0-9a-f]{40}$/i', $head) === 1
            ? strtolower($head)
            : substr(sha1($path), 0, 40);
    }

    private function resolveBranch(string $path): string
    {
        $override = trim((string) $this->option('branch'));

        if ($override !== '') {
            return $override;
        }

        $branch = $this->git($path, ['rev-parse', '--abbrev-ref', 'HEAD']);

        return $branch !== '' && $branch !== 'HEAD' ? $branch : 'working-tree';
    }

    /**
     * @param  list<string>  $arguments
     */
    private function git(string $path, array $arguments): string
    {
        if (! is_dir($path.DIRECTORY_SEPARATOR.'.git')) {
            return '';
        }

        $process = new Process(['git', ...$arguments], $path, ['GIT_OPTIONAL_LOCKS' => '0']);
        $process->setTimeout(10);
        $process->run();

        return $process->isSuccessful() ? trim($process->getOutput()) : '';
    }
}
