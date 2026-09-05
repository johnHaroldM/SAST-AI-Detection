<?php

namespace App\Http\Controllers;

use App\Models\Project;
use App\Services\ScanIngestionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Machine-facing ingestion for the CLI and CI pipelines.
 *
 * Separate from ScanController, which is session-authenticated for the SPA.
 * This endpoint authenticates a *project* via its ingest token rather than a
 * user, and can do nothing except create a scan for that one project — it
 * cannot read findings, list projects, or touch anything else. A token
 * leaked from a build agent is therefore write-only and single-project.
 *
 * Stateless, so it is registered outside the web group and takes no session
 * or CSRF token.
 */
class ScanIngestController extends Controller
{
    public function store(Request $request, ScanIngestionService $ingestion): JsonResponse
    {
        $project = $this->authenticateProject($request);

        if ($project === null) {
            return response()->json([
                'message' => 'Invalid or missing ingest token.',
            ], 401);
        }

        $validated = $request->validate([
            'source' => ['required', 'in:semgrep,sonarqube,bandit,phpcs,sarif'],
            'commit_sha' => ['required', 'string', 'size:40', 'regex:/^[0-9a-f]{40}$/i'],
            'branch' => ['required', 'string', 'max:255'],
            'report' => ['required', 'file', 'mimetypes:application/json,text/plain', 'max:51200'],
        ]);

        $scan = $ingestion->ingest([
            ...$validated,
            'project_id' => $project->id,
        ], $request->file('report'));

        $project->forceFill(['ingest_token_last_used_at' => now()])->save();

        return response()->json([
            'scan_id' => $scan->id,
            'project' => $project->name,
            'status' => $scan->status,
            'message' => 'Report accepted; parsing and scoring have been queued.',
        ], 202);
    }

    /**
     * Accepts either an Authorization: Bearer header or an X-Ingest-Token
     * header — the former is conventional, the latter avoids collisions with
     * proxies that rewrite Authorization.
     */
    private function authenticateProject(Request $request): ?Project
    {
        $token = $request->bearerToken() ?: $request->header('X-Ingest-Token', '');

        return Project::findByIngestToken((string) $token);
    }
}
