<?php

namespace App\Services\Scanner;

use App\Exceptions\LocalScanNotPermittedException;

/**
 * Decides whether a filesystem path may be scanned on request from the UI.
 *
 * Letting an authenticated user name a directory and then read its contents
 * back in a report is exactly the shape of an arbitrary-file-read primitive.
 * That is fine on a developer's own machine and unacceptable on a shared
 * server, so it is gated by config rather than assumed safe.
 */
class LocalScanGuard
{
    /**
     * @throws LocalScanNotPermittedException
     */
    public function assertScannable(string $path): string
    {
        if (! config('sast.scanner.local_scan.enabled')) {
            throw new LocalScanNotPermittedException(
                'Scanning local paths from the browser is disabled. Enable SAST_LOCAL_SCAN_ENABLED, or ingest a report through the API instead.'
            );
        }

        $resolved = realpath($path);

        if ($resolved === false || ! is_dir($resolved) || ! is_readable($resolved)) {
            throw new LocalScanNotPermittedException("Not a readable directory: {$path}");
        }

        $roots = (array) config('sast.scanner.local_scan.allowed_roots', []);

        if ($roots === []) {
            return $resolved;
        }

        foreach ($roots as $root) {
            $normalisedRoot = realpath(trim((string) $root));

            // Compare resolved paths so neither a symlink nor a ../ segment
            // can present an outside directory as an inside one.
            if ($normalisedRoot !== false && str_starts_with($this->normalise($resolved), $this->normalise($normalisedRoot))) {
                return $resolved;
            }
        }

        throw new LocalScanNotPermittedException(
            'That path is outside the directories this installation is allowed to scan.'
        );
    }

    private function normalise(string $path): string
    {
        return rtrim(str_replace('\\', '/', $path), '/').'/';
    }
}
