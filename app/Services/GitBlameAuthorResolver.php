<?php

namespace App\Services;

use Symfony\Component\Process\Process;

/**
 * Resolves the "developer_experience_lvl" feature by running `git blame`
 * on the offending line and checking how long that author has been
 * committing to the repo (a cheap proxy for seniority/familiarity,
 * used only as a weak signal in the feature vector — not a judgment
 * about any individual).
 *
 * Two caches matter here. A scan of a real project produces hundreds of
 * findings written by a handful of people, so counting an author's commits
 * once per repo instead of once per finding removes most of the work: a
 * 585-finding pass went from ~1,170 git invocations to roughly one blame per
 * finding plus one log per distinct author. Repo-root lookups are cached for
 * the same reason.
 */
class GitBlameAuthorResolver
{
    /** @var array<string, array<string, string>> repoRoot => author email => level */
    private array $levelByAuthor = [];

    /** @var array<string, string|null> directory => repo root */
    private array $repoRootCache = [];

    public function resolve(string $absoluteFilePath, int $lineNumber): string
    {
        $repoRoot = $this->findRepoRoot($absoluteFilePath);

        if ($repoRoot === null || ! is_readable($absoluteFilePath)) {
            return 'unknown';
        }

        $authorEmail = $this->blameAuthor($repoRoot, $absoluteFilePath, $lineNumber);

        if ($authorEmail === null) {
            return 'unknown';
        }

        return $this->levelByAuthor[$repoRoot][$authorEmail]
            ??= $this->classify($repoRoot, $authorEmail);
    }

    private function blameAuthor(string $repoRoot, string $absoluteFilePath, int $lineNumber): ?string
    {
        $process = $this->git($repoRoot, [
            'blame', '-L', "{$lineNumber},{$lineNumber}", '--porcelain', $absoluteFilePath,
        ]);

        $process->run();

        if (! $process->isSuccessful()) {
            return null;
        }

        return preg_match('/^author-mail <(.+?)>/m', $process->getOutput(), $matches) === 1
            ? $matches[1]
            : null;
    }

    private function classify(string $repoRoot, string $authorEmail): string
    {
        // --oneline still materialises one line per commit; asking git to
        // count directly avoids piping an entire history through PHP.
        $process = $this->git($repoRoot, ['rev-list', '--count', '--author='.$authorEmail, 'HEAD']);
        $process->run();

        $commitCount = $process->isSuccessful() ? (int) trim($process->getOutput()) : 0;

        return match (true) {
            $commitCount >= 200 => 'senior',
            $commitCount >= 30 => 'mid',
            default => 'junior',
        };
    }

    /**
     * @param  list<string>  $arguments
     */
    private function git(string $repoRoot, array $arguments): Process
    {
        $process = new Process(['git', ...$arguments], $repoRoot, [
            'GIT_TERMINAL_PROMPT' => '0',
            'GIT_OPTIONAL_LOCKS' => '0',
        ]);

        // A blame that hangs must not stall an entire ingestion run.
        $process->setTimeout((float) config('sast.scanner.git_timeout_seconds', 15));

        return $process;
    }

    private function findRepoRoot(string $path): ?string
    {
        $directory = is_dir($path) ? $path : dirname($path);

        if (array_key_exists($directory, $this->repoRootCache)) {
            return $this->repoRootCache[$directory];
        }

        $current = $directory;

        // dirname() on a Windows drive root returns itself, so the loop has to
        // terminate on "no longer changing" rather than on a POSIX "/".
        while ($current !== '' && is_dir($current)) {
            if (is_dir($current.DIRECTORY_SEPARATOR.'.git')) {
                return $this->repoRootCache[$directory] = $current;
            }

            $parent = dirname($current);

            if ($parent === $current) {
                break;
            }

            $current = $parent;
        }

        return $this->repoRootCache[$directory] = null;
    }
}
