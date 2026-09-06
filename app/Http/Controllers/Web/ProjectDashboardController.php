<?php

namespace App\Http\Controllers\Web;

use App\Exceptions\LocalScanNotPermittedException;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreProjectRequest;
use App\Models\Finding;
use App\Models\Project;
use App\Services\Scanner\OnDemandScanner;
use App\Services\Scanner\ScanTargetInspector;
use Illuminate\Http\RedirectResponse;
use Inertia\Inertia;
use Inertia\Response;

/**
 * What the scanner is pointed at, and what it found there.
 *
 * Projects are registered by absolute path, which makes it easy to lose track
 * of which codebase a finding came from — several of the registered projects
 * have files at identical relative paths. This page is the answer to "what is
 * it actually scanning".
 */
class ProjectDashboardController extends Controller
{
    public function index(ScanTargetInspector $inspector): Response
    {
        $projects = Project::query()
            ->withCount('scans')
            ->orderBy('name')
            ->get()
            ->map(function (Project $project) use ($inspector) {
                $scanIds = $project->scans()->pluck('id');

                $findings = Finding::whereIn('scan_id', $scanIds);
                $total = (clone $findings)->count();

                return [
                    'id' => $project->id,
                    'name' => $project->name,
                    'source_path' => $project->source_path,
                    'vcs_repo_slug' => $project->vcs_repo_slug,
                    'scans_count' => $project->scans_count,
                    'last_scanned_at' => $project->scans()->max('created_at'),
                    'ingest_token' => [
                        'exists' => $project->hasIngestToken(),
                        'hint' => $project->ingest_token_hint,
                        'created_at' => $project->ingest_token_created_at,
                        'last_used_at' => $project->ingest_token_last_used_at,
                        'expires_at' => $project->ingest_token_expires_at,
                        'expired' => $project->hasIngestToken() && $project->ingestTokenHasExpired(),
                    ],
                    'findings' => [
                        'total' => $total,
                        'labelled' => (clone $findings)->whereNotNull('final_label')->count(),
                        'true_positive' => (clone $findings)->where('final_label', 'true_positive')->count(),
                        'pending' => (clone $findings)->whereNull('final_label')->count(),
                    ],
                    'target' => $inspector->inspect($project),
                ];
            });

        return Inertia::render('Projects/Index', [
            'projects' => $projects,
            'excludedByConfig' => array_values((array) config('sast.scanner.exclude_directories', [])),
            'localScanEnabled' => (bool) config('sast.scanner.local_scan.enabled'),
        ]);
    }

    /**
     * Register a project from the UI rather than from tinker.
     */
    public function store(StoreProjectRequest $request): RedirectResponse
    {
        $project = Project::create($request->validated());

        return to_route('projects.index')
            ->with('success', "Registered {$project->name}. Scan it whenever you're ready.");
    }

    public function update(StoreProjectRequest $request, Project $project): RedirectResponse
    {
        $project->update($request->validated());

        return to_route('projects.index')->with('success', "Updated {$project->name}.");
    }

    /**
     * Issue an upload credential for CI or the CLI.
     *
     * Flashed rather than stored in plaintext: the hash is all the database
     * keeps, so this is the only moment the token can be read.
     */
    public function issueToken(Project $project): RedirectResponse
    {
        $token = $project->issueIngestToken();

        return to_route('projects.index')
            ->with('ingestToken', ['project' => $project->name, 'token' => $token]);
    }

    public function revokeToken(Project $project): RedirectResponse
    {
        $project->revokeIngestToken();

        return to_route('projects.index')
            ->with('success', "Upload token for {$project->name} revoked. Any CI job using it will now be rejected.");
    }

    /**
     * Scan now: read the code, ingest the findings, and land on the results.
     *
     * Runs inline rather than queued — a queued scan on a machine with no
     * worker running is indistinguishable from a broken one, and the whole
     * point of this action is that the user sees the outcome.
     */
    public function scan(Project $project, OnDemandScanner $scanner): RedirectResponse
    {
        try {
            $result = $scanner->scan($project);
        } catch (LocalScanNotPermittedException $e) {
            return back()->with('error', $e->getMessage());
        }

        if ($result['findings'] === 0) {
            return to_route('projects.index')->with(
                'success',
                "Scanned {$result['files']} files in {$project->name} — nothing flagged."
            );
        }

        return to_route('scans.show', $result['scan'])->with('success', sprintf(
            'Scanned %d files in %ss — %d findings. Expand any row for the report and the fix.',
            $result['files'],
            $result['seconds'],
            $result['findings'],
        ));
    }
}
