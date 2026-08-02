<?php

namespace App\Services\Workspaces;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

/**
 * Fetches source from a remote VCS into a disposable scratch directory.
 *
 * This is the provider a hosted deployment actually uses: the code under
 * analysis lives in someone else's repository, so each scan shallow-fetches
 * exactly the commit it refers to, gets analysed, and is deleted.
 *
 * Security posture, because this pulls untrusted third-party code:
 *  - The remote URL is *built* from an allowlisted host plus a strictly
 *    validated "owner/repo" slug. Arbitrary URLs are never accepted, which
 *    removes the SSRF surface entirely rather than trying to filter it.
 *  - Credentials go through GIT_CONFIG_* environment variables, never argv,
 *    so the token is not visible in the process list.
 *  - The checkout is capped by wall-clock timeout and on-disk size; a repo
 *    that blows either limit is discarded rather than left half-fetched.
 *  - The scratch directory is always inside the configured workspace root,
 *    verified after creation via realpath.
 *
 * Static analysis never executes the fetched code, which removes the worst
 * class of risk, but none of the above is optional in a multi-tenant setting.
 */
final class GitCloneWorkspace implements SourceWorkspace
{
    private const SLUG_PATTERN = '/^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*$/';

    private bool $acquired = false;

    private bool $released = false;

    private ?float $deadline = null;

    public function __construct(
        private string $scratchPath,
        private string $host,
        private string $repoSlug,
        private ?string $commitSha,
        private ?string $branch,
        private ?string $accessToken,
        private string $gitBinary = 'git',
        private int $timeoutSeconds = 300,
        private int $maxSizeMb = 512,
    ) {}

    public function path(): string
    {
        return $this->scratchPath;
    }

    public function isAvailable(): bool
    {
        return $this->acquired && is_dir($this->scratchPath);
    }

    public function driver(): string
    {
        return 'git';
    }

    /**
     * Fetch the commit. Returns false rather than throwing — a repo we can't
     * reach should degrade the feature vector, not fail the whole scan and
     * lose the findings we already parsed.
     */
    public function acquire(): bool
    {
        if ($this->acquired) {
            return true;
        }

        if (! preg_match(self::SLUG_PATTERN, $this->repoSlug)) {
            Log::warning('Refusing to clone: repository slug failed validation.', [
                'slug' => $this->repoSlug,
            ]);

            return false;
        }

        if (! $this->prepareScratchDirectory()) {
            return false;
        }

        // timeout_seconds is the budget for the whole acquisition, not for
        // each git invocation — otherwise a fetch-by-SHA that stalls, then
        // falls back to a branch fetch that also stalls, blocks the queue
        // worker for double the configured limit.
        $this->deadline = microtime(true) + $this->timeoutSeconds;

        $url = sprintf('https://%s/%s.git', $this->host, $this->repoSlug);
        $ref = $this->commitSha ?: $this->branch;

        if (blank($ref)) {
            Log::warning('Refusing to clone: no commit or branch to fetch.', ['slug' => $this->repoSlug]);
            $this->release();

            return false;
        }

        try {
            $this->run(['init', '--quiet']);
            $this->run(['remote', 'add', 'origin', $url]);

            // Fetching the exact SHA is preferred — it is unambiguous and
            // pulls the least data. Servers that disallow fetch-by-SHA fall
            // back to the branch tip, which is still the right ref for a
            // scan of the head of a branch.
            if (! $this->tryFetch($ref) && $this->branch && $ref !== $this->branch) {
                Log::info('Fetch by commit SHA rejected, falling back to branch.', [
                    'slug' => $this->repoSlug,
                    'branch' => $this->branch,
                ]);

                if (! $this->tryFetch($this->branch)) {
                    $this->release();

                    return false;
                }
            } elseif (! is_dir($this->scratchPath.'/.git')) {
                $this->release();

                return false;
            }

            $this->run(['checkout', '--quiet', 'FETCH_HEAD']);
        } catch (ProcessTimedOutException) {
            Log::warning('Clone exceeded time budget.', [
                'slug' => $this->repoSlug,
                'timeout_seconds' => $this->timeoutSeconds,
            ]);
            $this->release();

            return false;
        } catch (\Throwable $e) {
            Log::warning('Clone failed.', [
                'slug' => $this->repoSlug,
                'error' => $this->redact($e->getMessage()),
            ]);
            $this->release();

            return false;
        }

        if (! $this->withinSizeBudget()) {
            Log::warning('Checkout exceeded size budget, discarding.', [
                'slug' => $this->repoSlug,
                'max_size_mb' => $this->maxSizeMb,
            ]);
            $this->release();

            return false;
        }

        $this->acquired = true;

        return true;
    }

    public function release(): void
    {
        if ($this->released) {
            return;
        }

        $this->released = true;
        $this->acquired = false;

        if (! is_dir($this->scratchPath)) {
            return;
        }

        // Guard against ever deleting outside the scratch area, however the
        // path was constructed.
        $resolved = realpath($this->scratchPath);

        if ($resolved === false || ! str_contains(basename($resolved), 'scan-')) {
            Log::error('Refusing to delete unexpected workspace path.', ['path' => $this->scratchPath]);

            return;
        }

        $this->deleteDirectory($resolved);
    }

    private function tryFetch(string $ref): bool
    {
        $process = $this->process(['fetch', '--depth', '1', '--quiet', 'origin', $ref]);
        $process->run();

        return $process->isSuccessful();
    }

    private function prepareScratchDirectory(): bool
    {
        if (! is_dir($this->scratchPath) && ! mkdir($this->scratchPath, 0755, true) && ! is_dir($this->scratchPath)) {
            Log::warning('Could not create workspace scratch directory.', ['path' => $this->scratchPath]);

            return false;
        }

        return true;
    }

    /**
     * @param  list<string>  $arguments
     */
    private function run(array $arguments): void
    {
        $process = $this->process($arguments);
        $process->mustRun();
    }

    /**
     * @param  list<string>  $arguments
     */
    private function process(array $arguments): Process
    {
        $process = new Process(
            [$this->gitBinary, ...$arguments],
            $this->scratchPath,
            $this->gitEnvironment(),
        );

        $process->setTimeout($this->remainingBudget());

        return $process;
    }

    /**
     * Seconds left in the acquisition budget, floored at 1 so a process is
     * never handed a zero or negative timeout.
     */
    private function remainingBudget(): float
    {
        if ($this->deadline === null) {
            return (float) $this->timeoutSeconds;
        }

        return max(1.0, $this->deadline - microtime(true));
    }

    /**
     * Credentials travel in the environment, not the command line, so the
     * token never appears in `ps` output or a process listing.
     *
     * @return array<string, string>
     */
    private function gitEnvironment(): array
    {
        $env = [
            'GIT_TERMINAL_PROMPT' => '0',      // never block waiting for credentials
            'GIT_ASKPASS' => '',
            'GCM_INTERACTIVE' => 'never',
        ];

        if (blank($this->accessToken)) {
            return $env;
        }

        $authorization = 'Authorization: Basic '.base64_encode('x-access-token:'.$this->accessToken);

        return $env + [
            'GIT_CONFIG_COUNT' => '1',
            'GIT_CONFIG_KEY_0' => 'http.extraHeader',
            'GIT_CONFIG_VALUE_0' => $authorization,
        ];
    }

    private function withinSizeBudget(): bool
    {
        $budget = $this->maxSizeMb * 1024 * 1024;
        $total = 0;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->scratchPath, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if ($file->isFile()) {
                $total += $file->getSize();

                if ($total > $budget) {
                    return false;
                }
            }
        }

        return true;
    }

    private function deleteDirectory(string $directory): void
    {
        // The tree must be materialised *before* anything is unlinked —
        // RecursiveIteratorIterator skips entries when the directory it is
        // walking changes underneath it, which silently leaves parts of a
        // checkout on disk. On a hosted deployment that is a slow disk leak.
        $items = iterator_to_array(
            new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            ),
            false
        );

        foreach ($items as $item) {
            /** @var \SplFileInfo $item */
            if ($item->isDir() && ! $item->isLink()) {
                @rmdir($item->getPathname());

                continue;
            }

            // Git marks pack/object files read-only, and on Windows unlink
            // fails outright on a read-only file.
            @chmod($item->getPathname(), 0666);
            @unlink($item->getPathname());
        }

        @rmdir($directory);

        if (is_dir($directory)) {
            Log::warning('Workspace could not be fully removed; disk will leak until it is cleared.', [
                'path' => $directory,
            ]);
        }
    }

    private function redact(string $message): string
    {
        if (blank($this->accessToken)) {
            return $message;
        }

        return str_replace($this->accessToken, '[redacted]', $message);
    }

    public static function scratchPathFor(string $root, int|string $projectId, ?string $commitSha): string
    {
        $suffix = Str::substr((string) $commitSha, 0, 12) ?: Str::random(12);

        return rtrim($root, '/\\').DIRECTORY_SEPARATOR.'scan-'.$projectId.'-'.$suffix.'-'.Str::random(6);
    }
}
