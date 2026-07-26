<?php

namespace App\Console\Commands;

use App\Models\Finding;
use App\Services\FeatureVectorBuilder;
use Illuminate\Console\Command;

/**
 * Backfills feature_vector for any findings that predate the ML pipeline
 * (e.g. imported from historical audit logs or a synthetic benchmark like
 * Juliet Test Suite) so they can be used as initial training data before
 * the app has accumulated live triage feedback.
 */
class BuildDatasetCommand extends Command
{
    protected $signature = 'sast:build-dataset
        {--project= : Limit to a single project ID}
        {--chunk=200 : Number of findings to process per batch}';

    protected $description = 'Backfill feature vectors for findings missing them, in preparation for initial model training';

    public function handle(FeatureVectorBuilder $vectorBuilder): int
    {
        $query = Finding::query()->whereNull('feature_vector')->with('scan');

        if ($projectId = $this->option('project')) {
            $query->whereHas('scan', fn ($q) => $q->where('project_id', $projectId));
        }

        $total = $query->count();

        if ($total === 0) {
            $this->info('No findings require feature vector backfill.');
            return self::SUCCESS;
        }

        $bar = $this->output->createProgressBar($total);
        $bar->start();

        $query->chunkById((int) $this->option('chunk'), function ($findings) use ($vectorBuilder, $bar) {
            $byProject = $findings->groupBy(fn (Finding $f) => $f->scan->project_id);

            foreach ($byProject as $projectId => $projectFindings) {
                $projectRoot = storage_path("app/workspaces/{$projectId}/backfill");
                $vectorBuilder->buildBatch($projectFindings, $projectRoot);
                $bar->advance($projectFindings->count());
            }
        });

        $bar->finish();
        $this->newLine(2);
        $this->info("Backfilled feature vectors for {$total} findings.");
        $this->comment('Next: label enough of these via the triage UI (or a bulk import), then run `php artisan sast:train`.');

        return self::SUCCESS;
    }
}
