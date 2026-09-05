<?php

namespace App\Services\Workspaces;

use App\Models\Scan;
use Illuminate\Support\Facades\Log;

/**
 * Chooses how to obtain source for a given scan.
 *
 * Resolution order under the default 'auto' driver:
 *   1. The project names a local source_path that exists  -> LocalPathWorkspace
 *   2. A cached checkout already sits in the workspace root -> LocalPathWorkspace
 *   3. Git is enabled and the project has a repo slug     -> GitCloneWorkspace
 *   4. Otherwise                                          -> NullWorkspace
 *
 * Local paths win over cloning so a developer can point the scanner at a
 * working copy without credentials, while a hosted deployment — where no
 * local path is ever set — lands on git every time.
 */
class SourceWorkspaceFactory
{
    public function for(Scan $scan): SourceWorkspace
    {
        $driver = (string) config('sast.workspace.driver', 'auto');

        return match ($driver) {
            'none' => $this->none($scan, 'workspace driver is disabled'),
            'local' => $this->local($scan) ?? $this->none($scan, 'no local source path configured'),
            'git' => $this->git($scan) ?? $this->none($scan, 'git workspace unavailable'),
            default => $this->local($scan)
                ?? $this->git($scan)
                ?? $this->none($scan, 'no local checkout and no usable repository credentials'),
        };
    }

    private function local(Scan $scan): ?SourceWorkspace
    {
        foreach ($this->candidatePaths($scan) as $candidate) {
            if (blank($candidate)) {
                continue;
            }

            $workspace = new LocalPathWorkspace($candidate);

            if ($workspace->isAvailable()) {
                return $workspace;
            }
        }

        return null;
    }

    private function git(Scan $scan): ?SourceWorkspace
    {
        if (! config('sast.workspace.git.enabled')) {
            return null;
        }

        $project = $scan->project;

        if ($project === null || blank($project->vcs_repo_slug)) {
            return null;
        }

        $host = $project->vcs_host ?: (string) config('sast.workspace.git.default_host', 'github.com');
        $allowed = (array) config('sast.workspace.git.allowed_hosts', []);

        if (! in_array($host, $allowed, true)) {
            Log::warning('Refusing to clone from a host outside the allowlist.', [
                'scan_id' => $scan->id,
                'host' => $host,
            ]);

            return null;
        }

        $workspace = new GitCloneWorkspace(
            scratchPath: GitCloneWorkspace::scratchPathFor(
                $this->workspaceRoot(),
                $scan->project_id,
                $scan->commit_sha,
            ),
            host: $host,
            repoSlug: (string) $project->vcs_repo_slug,
            commitSha: $scan->commit_sha,
            branch: $scan->branch,
            accessToken: $project->vcs_access_token,
            gitBinary: (string) config('sast.workspace.git.binary', 'git'),
            timeoutSeconds: (int) config('sast.workspace.git.timeout_seconds', 300),
            maxSizeMb: (int) config('sast.workspace.git.max_size_mb', 512),
        );

        return $workspace->acquire() ? $workspace : null;
    }

    private function none(Scan $scan, string $reason): NullWorkspace
    {
        Log::warning('Scan will be enriched without source — AST and blame features fall back to defaults.', [
            'scan_id' => $scan->id,
            'project_id' => $scan->project_id,
            'reason' => $reason,
        ]);

        return new NullWorkspace(
            $this->workspaceRoot().DIRECTORY_SEPARATOR.$scan->project_id,
            $reason,
        );
    }

    /**
     * @return list<string|null>
     */
    private function candidatePaths(Scan $scan): array
    {
        $root = $this->workspaceRoot();

        return [
            $scan->project?->source_path,
            "{$root}/{$scan->project_id}/{$scan->commit_sha}",
            "{$root}/{$scan->project_id}",
        ];
    }

    private function workspaceRoot(): string
    {
        return rtrim(
            (string) config('sast.workspace.root', storage_path('app/workspaces')),
            '/\\'
        );
    }
}
