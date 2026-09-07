<?php

namespace App\Console\Commands;

use App\Services\AI\AiTrainingDatasetExporter;
use Illuminate\Console\Command;
use InvalidArgumentException;
use RuntimeException;

class ExportAiTrainingDatasetCommand extends Command
{
    protected $signature = 'sast:export-ai-feedback
        {--reviewer=all : Export all reviewers, ATAKE only, or DEPENSA only}
        {--output= : Relative directory on the local storage disk}
        {--validation-percent=20 : Stable project/commit groups assigned to validation}';

    protected $description = 'Export trusted human feedback for ATAKE and DEPENSA as JSONL training datasets';

    public function handle(AiTrainingDatasetExporter $exporter): int
    {
        $reviewer = (string) $this->option('reviewer');
        $output = $this->option('output');
        $validationPercent = filter_var(
            $this->option('validation-percent'),
            FILTER_VALIDATE_INT,
        );

        if ($validationPercent === false) {
            $this->error('Validation percent must be an integer between 0 and 50.');

            return self::FAILURE;
        }

        try {
            $manifest = $exporter->export(
                $reviewer,
                is_string($output) ? $output : null,
                $validationPercent,
            );
        } catch (InvalidArgumentException|RuntimeException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $count = (int) $manifest['record_count'];
        $this->info("Exported {$count} trusted AI feedback record(s).");
        $this->line('Local storage: '.$manifest['output_directory'].'/manifest.json');

        return self::SUCCESS;
    }
}
