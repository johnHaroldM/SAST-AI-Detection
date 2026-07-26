<?php

namespace App\Services;

use Symfony\Component\Process\Process;

/**
 * Resolves the "developer_experience_lvl" feature by running `git blame`
 * on the offending line and checking how long that author has been
 * committing to the repo (a cheap proxy for seniority/familiarity,
 * used only as a weak signal in the feature vector — not a judgment
 * about any individual).
 */
class GitBlameAuthorResolver
{
    public function resolve(string $absoluteFilePath, int $lineNumber): string
    {
        $repoRoot = $this->findRepoRoot($absoluteFilePath);

        if ($repoRoot === null || !is_readable($absoluteFilePath)) {
            return 'unknown';
        }

        $process = new Process([
            'git', 'blame', '-L', "{$lineNumber},{$lineNumber}", '--porcelain', $absoluteFilePath,
        ], $repoRoot);

        $process->run();

        if (!$process->isSuccessful()) {
            return 'unknown';
        }

        if (!preg_match('/^author-mail <(.+?)>/m', $process->getOutput(), $matches)) {
            return 'unknown';
        }

        $authorEmail = $matches[1];

        $countProcess = new Process([
            'git', 'log', '--author=' . $authorEmail, '--oneline',
        ], $repoRoot);
        $countProcess->run();

        $commitCount = $countProcess->isSuccessful()
            ? count(array_filter(explode("\n", trim($countProcess->getOutput()))))
            : 0;

        return match (true) {
            $commitCount >= 200 => 'senior',
            $commitCount >= 30  => 'mid',
            default             => 'junior',
        };
    }

    private function findRepoRoot(string $path): ?string
    {
        $dir = is_dir($path) ? $path : dirname($path);

        while ($dir !== '/' && $dir !== '') {
            if (is_dir($dir . '/.git')) {
                return $dir;
            }
            $dir = dirname($dir);
        }

        return null;
    }
}
