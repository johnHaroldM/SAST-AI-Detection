<?php

namespace App\Jobs;

use App\Models\Finding;
use App\Models\Scan;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Posts inline PR review comments only for predictions the architecture
 * doc specifies: predicted_label = true_positive AND confidence > 80%.
 * Everything below that threshold stays in the in-app triage queue
 * instead of adding noise to the developer's PR.
 */
class PostPrCommentsJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 5;

    /** @var list<int> */
    public array $backoff = [10, 30, 60, 120, 300];

    public function __construct(public Scan $scan) {}

    public function handle(): void
    {
        $project = $this->scan->project;

        if ($project === null || blank($project->vcs_repo_slug) || blank($project->vcs_access_token)) {
            Log::info('Skipping PR comments — project has no VCS credentials configured.', [
                'scan_id' => $this->scan->id,
            ]);

            return;
        }

        $candidates = $this->scan->findings()
            ->where('predicted_label', 'true_positive')
            ->where('tp_probability', '>', (float) config('sast.pr_comments.confidence_threshold', 0.80))
            ->where('status', 'pending')
            ->get();

        if ($candidates->isEmpty()) {
            return;
        }

        foreach ($candidates as $finding) {
            $this->postComment((string) $project->vcs_repo_slug, (string) $project->vcs_access_token, $finding);
        }
    }

    private function postComment(string $repo, string $token, Finding $finding): void
    {
        $body = $this->buildCommentBody($finding);

        $response = Http::withToken($token)
            ->post("https://api.github.com/repos/{$repo}/commits/{$this->scan->commit_sha}/comments", [
                'body' => $body,
                'path' => $finding->file_path,
                'line' => $finding->line_number,
            ]);

        if ($response->failed()) {
            Log::warning('Failed to post PR comment for finding', [
                'finding_id' => $finding->id,
                'status' => $response->status(),
            ]);

            return;
        }

        $finding->update(['status' => 'reported']);
    }

    private function buildCommentBody(Finding $finding): string
    {
        $confidencePct = round($finding->tp_probability * 100);

        return <<<MD
        **🔒 SAST Triage Engine — likely true positive ({$confidencePct}% confidence)**

        {$finding->message}

        Rule: `{$finding->rule_id}` · CWE-{$finding->cwe_id} · Severity: {$finding->severity}

        _This finding was auto-flagged by the ML triage model based on historical rule accuracy and code context. React with a triage decision in the dashboard to help retrain the model._
        MD;
    }
}
