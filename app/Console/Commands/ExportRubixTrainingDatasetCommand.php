<?php

namespace App\Console\Commands;

use App\Services\RubixTrainingDatasetExporter;
use Illuminate\Console\Command;
use InvalidArgumentException;
use RuntimeException;

class ExportRubixTrainingDatasetCommand extends Command
{
    protected $signature = 'sast:export-rubix-dataset
        {--output= : New relative directory on the private local storage disk}
        {--validation-percent= : Stable project/commit groups assigned to validation (defaults to config)}
        {--review-limit=500 : Maximum deduplicated unlabeled findings; use 0 for all}';

    protected $description = 'Export trusted Rubix partitions, a human review queue, and quarantined weak labels';

    public function handle(RubixTrainingDatasetExporter $exporter): int
    {
        $validationPercent = $this->integerOption(
            'validation-percent',
            (int) config('sast.training.validation_percent', 20),
        );
        $reviewLimit = $this->integerOption('review-limit', 500);

        if ($validationPercent === null) {
            $this->error('Validation percent must be an integer between 1 and 50.');

            return self::FAILURE;
        }

        if ($reviewLimit === null) {
            $this->error('Review limit must be an integer of zero or greater.');

            return self::FAILURE;
        }

        $output = $this->option('output');

        try {
            $manifest = $exporter->export(
                is_string($output) ? $output : null,
                $validationPercent,
                $reviewLimit,
            );
        } catch (InvalidArgumentException|RuntimeException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $counts = is_array($manifest['counts'] ?? null) ? $manifest['counts'] : [];
        $this->info(sprintf(
            'Exported %d training, %d validation, and %d review record(s).',
            (int) ($counts['train'] ?? 0),
            (int) ($counts['validation'] ?? 0),
            (int) ($counts['review_queue'] ?? 0),
        ));

        if ((int) ($counts['quarantine'] ?? 0) > 0) {
            $this->warn((int) $counts['quarantine'].' weak or unattributed label(s) were quarantined.');
        }

        $this->line('Private local storage: '.$manifest['output_directory'].'/manifest.json');

        return self::SUCCESS;
    }

    private function integerOption(string $name, int $default): ?int
    {
        $value = $this->option($name);

        if ($value === null || $value === '') {
            return $default;
        }

        $validated = filter_var($value, FILTER_VALIDATE_INT);

        return $validated === false ? null : $validated;
    }
}
