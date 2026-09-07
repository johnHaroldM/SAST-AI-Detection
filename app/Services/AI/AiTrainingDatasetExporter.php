<?php

namespace App\Services\AI;

use App\Models\AiAssessment;
use App\Models\AiAssessmentFeedback;
use App\Models\TriageFeedback;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Facades\Storage;
use InvalidArgumentException;
use RuntimeException;

final class AiTrainingDatasetExporter
{
    public const SCHEMA_VERSION = '1.0';

    /** @var list<string> */
    private const PSEUDO_LABEL_NOTE_PREFIXES = [
        'AI training label from ATAKE/DEPENSA adjudicator',
        'AI_PROMOTED',
    ];

    /** @var list<string> */
    private const REVIEWERS = ['atake', 'depensa'];

    /** @var list<string> */
    private const CLASSIFICATIONS = [
        'confirmed_tp',
        'likely_tp',
        'needs_validation',
        'likely_fp',
        'confirmed_fp',
        'unresolved',
    ];

    /** @var list<string> */
    private const OUTCOMES = [
        'true_positive',
        'false_positive',
        'true_negative',
        'false_negative',
        'unresolved',
    ];

    public function __construct(
        private readonly SecretRedactor $redactor = new SecretRedactor,
    ) {}

    /**
     * Export human-reviewed ATAKE/DEPENSA examples to the local disk.
     *
     * @return array<string, mixed> The manifest written alongside the JSONL files.
     */
    public function export(
        string $reviewer = 'all',
        ?string $outputDirectory = null,
        int $validationPercent = 20,
    ): array {
        $reviewers = $this->reviewers($reviewer);
        $this->validateValidationPercent($validationPercent);

        $directory = $this->outputDirectory($outputDirectory);
        $recordsByReviewer = array_fill_keys($reviewers, []);

        foreach ($this->records($reviewers, $validationPercent) as $record) {
            $recordsByReviewer[$record['reviewer']][] = $record;
        }

        foreach ($recordsByReviewer as &$records) {
            usort($records, static fn (array $left, array $right): int => [
                $left['context_hash'],
                $left['assessment_id'],
            ] <=> [
                $right['context_hash'],
                $right['assessment_id'],
            ]);
        }
        unset($records);

        [$files, $payloads] = $this->jsonlFiles($directory, $recordsByReviewer);
        $manifest = $this->manifest(
            $directory,
            $reviewer,
            $validationPercent,
            $recordsByReviewer,
            $files,
        );

        $manifestPayload = $this->encode($manifest, pretty: true)."\n";
        $disk = Storage::disk('local');

        foreach ($payloads as $path => $payload) {
            if (! $disk->put($path, $payload)) {
                throw new RuntimeException("Unable to write AI training dataset file [{$path}].");
            }
        }

        $manifestPath = $directory.'/manifest.json';

        if (! $disk->put($manifestPath, $manifestPayload)) {
            throw new RuntimeException("Unable to write AI training dataset manifest [{$manifestPath}].");
        }

        return $manifest;
    }

    /**
     * @param  list<string>  $reviewers
     * @return list<array<string, mixed>>
     */
    private function records(array $reviewers, int $validationPercent): array
    {
        $assessments = AiAssessment::query()
            ->whereIn('reviewer', $reviewers)
            ->whereNotNull('completed_at')
            ->whereHas('finding.aiContext')
            ->with([
                'feedback' => fn ($query) => $query
                    ->orderByDesc('reviewed_at')
                    ->orderByDesc('id'),
                'finding.aiContext',
                'finding.scan',
            ])
            ->orderByDesc('completed_at')
            ->orderByDesc('id')
            ->get();

        $triageFeedback = $this->trustedTriageFeedback($assessments);
        $records = [];
        $seen = [];

        foreach ($assessments as $assessment) {
            $finding = $assessment->finding;
            $context = $finding?->aiContext;
            $scan = $finding?->scan;

            if ($finding === null || $context === null || $scan === null) {
                continue;
            }

            $signal = $this->humanSignal(
                $assessment,
                $triageFeedback[(int) $finding->getKey()] ?? null,
            );

            if ($signal === null) {
                continue;
            }

            $contextHash = (string) $context->context_hash;

            // An assessment is useful for supervised training only when its
            // stored fingerprint still matches the exact context being
            // exported. Context snapshots can be rebuilt after prompt-format
            // upgrades, and pairing an old answer with new input would poison
            // the dataset.
            if (
                ! is_string($assessment->context_hash)
                || ! hash_equals($assessment->context_hash, $contextHash)
            ) {
                continue;
            }

            $dedupeKey = $assessment->reviewer."\0".$contextHash;

            if (isset($seen[$dedupeKey])) {
                continue;
            }

            $seen[$dedupeKey] = true;
            $referenceLabel = $this->classificationLabel($signal['reference_classification'])
                ?? $signal['reference_label'];
            $inputContext = $this->redactContext((string) $context->context);

            $records[] = [
                'schema_version' => self::SCHEMA_VERSION,
                'reviewer' => $assessment->reviewer,
                'model' => $assessment->model,
                'model_version' => $assessment->model_version,
                'prompt_version' => $assessment->prompt_version,
                'context_hash' => $contextHash,
                'input_context_sha256' => hash('sha256', $inputContext),
                'split' => $this->split(
                    (int) $scan->project_id,
                    (string) $scan->commit_sha,
                    $validationPercent,
                ),
                'project_id' => (int) $scan->project_id,
                'scan_id' => (int) $scan->getKey(),
                'finding_id' => (int) $finding->getKey(),
                'assessment_id' => (int) $assessment->getKey(),
                'commit_sha' => (string) $scan->commit_sha,
                'rule_id' => $finding->rule_id,
                'cwe_id' => $finding->cwe_id === null ? null : (int) $finding->cwe_id,
                'severity' => $finding->severity,
                'input_context' => $inputContext,
                'original_output' => $this->originalOutput($assessment),
                'reference_classification' => $signal['reference_classification'],
                'reference_label' => $referenceLabel,
                'verdict' => $signal['verdict'],
                'outcome' => $this->outcome($assessment->classification, $referenceLabel),
                'rubix_evaluation_outcome' => $assessment->evaluation_outcome,
                'reason_codes' => $signal['reason_codes'],
                'notes' => $this->redactNullable($signal['notes']),
                'feedback_source' => $signal['source'],
                'reviewed_at' => $signal['reviewed_at'],
                'completed_at' => $assessment->completed_at?->toIso8601String(),
            ];
        }

        return $records;
    }

    /**
     * @param  EloquentCollection<int, AiAssessment>  $assessments
     * @return array<int, TriageFeedback>
     */
    private function trustedTriageFeedback(EloquentCollection $assessments): array
    {
        $findingIds = $assessments
            ->pluck('finding_id')
            ->map(static fn (mixed $id): int => (int) $id)
            ->unique()
            ->values();

        if ($findingIds->isEmpty()) {
            return [];
        }

        $feedbackByFinding = [];

        foreach (TriageFeedback::query()
            ->whereIn('finding_id', $findingIds)
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->get() as $feedback) {
            $findingId = (int) $feedback->finding_id;

            if (
                isset($feedbackByFinding[$findingId])
                || $feedback->source === 'ai_pseudo'
                || $this->hasPseudoLabelNote((string) $feedback->notes)
            ) {
                continue;
            }

            $feedbackByFinding[$findingId] = $feedback;
        }

        return $feedbackByFinding;
    }

    private function hasPseudoLabelNote(string $notes): bool
    {
        foreach (self::PSEUDO_LABEL_NOTE_PREFIXES as $prefix) {
            if (str_starts_with($notes, $prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{
     *     reference_classification:?string,
     *     reference_label:?string,
     *     verdict:?string,
     *     reason_codes:list<mixed>,
     *     notes:?string,
     *     source:string,
     *     reviewed_at:?string
     * }|null
     */
    private function humanSignal(
        AiAssessment $assessment,
        ?TriageFeedback $triageFeedback,
    ): ?array {
        $explicitFeedback = $assessment->feedback->first();

        if ($explicitFeedback instanceof AiAssessmentFeedback) {
            $referenceClassification = $explicitFeedback->corrected_classification;

            if ($referenceClassification === null && $explicitFeedback->verdict === 'correct') {
                $referenceClassification = $assessment->classification;
            }

            return [
                'reference_classification' => $referenceClassification,
                'reference_label' => $this->classificationLabel($referenceClassification),
                'verdict' => $explicitFeedback->verdict,
                'reason_codes' => is_array($explicitFeedback->reason_codes)
                    ? array_values($explicitFeedback->reason_codes)
                    : [],
                'notes' => $explicitFeedback->notes,
                'source' => 'ai_assessment_feedback',
                'reviewed_at' => $explicitFeedback->reviewed_at->toIso8601String(),
            ];
        }

        $finding = $assessment->finding;

        if ($triageFeedback === null || $finding?->final_label === null) {
            return null;
        }

        return [
            'reference_classification' => $finding->final_label === 'true_positive'
                ? 'confirmed_tp'
                : 'confirmed_fp',
            'reference_label' => $finding->final_label,
            'verdict' => null,
            'reason_codes' => [],
            'notes' => $triageFeedback->notes,
            'source' => 'triage_feedback',
            'reviewed_at' => $triageFeedback->updated_at->toIso8601String(),
        ];
    }

    /** @return array<string, mixed> */
    private function originalOutput(AiAssessment $assessment): array
    {
        return $this->redactValue([
            'classification' => $assessment->classification,
            'confidence' => $assessment->confidence,
            'attacker_controlled' => $assessment->attacker_controlled,
            'sink_reachable' => $assessment->sink_reachable,
            'mitigation_detected' => $assessment->mitigation_detected,
            'preconditions' => $assessment->preconditions,
            'supporting_evidence' => $assessment->supporting_evidence,
            'contradicting_evidence' => $assessment->contradicting_evidence,
            'missing_evidence' => $assessment->missing_evidence,
            'remediation' => $assessment->remediation,
            'reasoning_summary' => $assessment->reasoning_summary,
        ]);
    }

    private function classificationLabel(?string $classification): ?string
    {
        return match ($classification) {
            'confirmed_tp', 'likely_tp' => 'true_positive',
            'confirmed_fp', 'likely_fp' => 'false_positive',
            default => null,
        };
    }

    private function outcome(?string $classification, ?string $referenceLabel): string
    {
        $predictedLabel = $this->classificationLabel($classification);

        if ($predictedLabel === null || $referenceLabel === null) {
            return 'unresolved';
        }

        if ($predictedLabel === 'true_positive') {
            return $referenceLabel === 'true_positive' ? 'true_positive' : 'false_positive';
        }

        return $referenceLabel === 'true_positive' ? 'false_negative' : 'true_negative';
    }

    private function split(int $projectId, string $commitSha, int $validationPercent): string
    {
        $groupHash = hash('sha256', $projectId."\0".strtolower(trim($commitSha)));
        $bucket = hexdec(substr($groupHash, 0, 8)) % 100;

        return $bucket < $validationPercent ? 'validation' : 'train';
    }

    /**
     * @param  array<string, list<array<string, mixed>>>  $recordsByReviewer
     * @return array{0:array<string, array<string, mixed>>,1:array<string, string>}
     */
    private function jsonlFiles(string $directory, array $recordsByReviewer): array
    {
        $files = [];
        $payloads = [];

        foreach ($recordsByReviewer as $reviewer => $records) {
            $filename = $reviewer.'.jsonl';
            $path = $directory.'/'.$filename;
            $payload = '';

            foreach ($records as $record) {
                $payload .= $this->encode($record)."\n";
            }

            $payloads[$path] = $payload;
            $files[$filename] = [
                'reviewer' => $reviewer,
                'path' => $path,
                'records' => count($records),
                'bytes' => strlen($payload),
                'sha256' => hash('sha256', $payload),
            ];
        }

        return [$files, $payloads];
    }

    /**
     * @param  array<string, list<array<string, mixed>>>  $recordsByReviewer
     * @param  array<string, array<string, mixed>>  $files
     * @return array<string, mixed>
     */
    private function manifest(
        string $directory,
        string $reviewer,
        int $validationPercent,
        array $recordsByReviewer,
        array $files,
    ): array {
        $reviewerCounts = array_fill_keys(array_keys($recordsByReviewer), 0);
        $splitCounts = ['train' => 0, 'validation' => 0];
        $classes = array_fill_keys(self::CLASSIFICATIONS, 0);
        $labels = ['true_positive' => 0, 'false_positive' => 0, 'unresolved' => 0];
        $outcomes = array_fill_keys(self::OUTCOMES, 0);
        $verdicts = array_fill_keys([...AiAssessmentFeedback::VERDICTS, 'not_explicit'], 0);
        $total = 0;

        foreach ($recordsByReviewer as $recordReviewer => $records) {
            foreach ($records as $record) {
                $total++;
                $reviewerCounts[$recordReviewer]++;
                $splitCounts[$record['split']]++;
                $classes[$record['reference_classification'] ?? 'unresolved']++;
                $labels[$record['reference_label'] ?? 'unresolved']++;
                $outcomes[$record['outcome']]++;
                $verdicts[$record['verdict'] ?? 'not_explicit']++;
            }
        }

        return [
            'schema_version' => self::SCHEMA_VERSION,
            'generated_at' => now()->toIso8601String(),
            'output_directory' => $directory,
            'reviewer_filter' => strtolower(trim($reviewer)),
            'validation_percent' => $validationPercent,
            'split_strategy' => 'sha256(project_id + NUL + lowercase(commit_sha)) modulo 100',
            'record_count' => $total,
            'counts' => [
                'total' => $total,
                'reviewers' => $reviewerCounts,
                'splits' => $splitCounts,
            ],
            'classes' => $classes,
            'labels' => $labels,
            'outcomes' => $outcomes,
            'verdicts' => $verdicts,
            'files' => $files,
        ];
    }

    /** @return list<string> */
    private function reviewers(string $reviewer): array
    {
        $normalized = strtolower(trim($reviewer));

        if ($normalized === 'all') {
            return self::REVIEWERS;
        }

        if (! in_array($normalized, self::REVIEWERS, true)) {
            throw new InvalidArgumentException('Reviewer must be one of: all, atake, depensa.');
        }

        return [$normalized];
    }

    private function validateValidationPercent(int $validationPercent): void
    {
        if ($validationPercent < 0 || $validationPercent > 50) {
            throw new InvalidArgumentException('Validation percent must be between 0 and 50.');
        }
    }

    private function outputDirectory(?string $outputDirectory): string
    {
        if ($outputDirectory === null || trim($outputDirectory) === '') {
            return 'anino-training/'.now()->format('Ymd_His_u');
        }

        $normalized = str_replace('\\', '/', trim($outputDirectory));

        if (
            str_contains($normalized, "\0")
            || preg_match('#^(?:/|[A-Za-z]:/|//)#', $normalized) === 1
            || collect(explode('/', $normalized))->contains(
                static fn (string $segment): bool => $segment === '..' || $segment === '.',
            )
        ) {
            throw new InvalidArgumentException('Output must be a relative local-storage directory without traversal segments.');
        }

        return rtrim($normalized, '/');
    }

    /** @param array<array-key, mixed> $value */
    private function encode(array $value, bool $pretty = false): string
    {
        $flags = JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE
            | JSON_PRESERVE_ZERO_FRACTION
            | JSON_INVALID_UTF8_SUBSTITUTE
            | JSON_THROW_ON_ERROR;

        if ($pretty) {
            $flags |= JSON_PRETTY_PRINT;
        }

        return json_encode($value, $flags);
    }

    private function redactNullable(?string $value): ?string
    {
        return $value === null ? null : $this->redactor->redact($value);
    }

    private function redactContext(string $context): string
    {
        $decoded = json_decode($context, true);

        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
            return $this->encode($this->redactValue($decoded));
        }

        return $this->redactor->redact($context);
    }

    private function redactValue(mixed $value): mixed
    {
        if (is_string($value)) {
            return $this->redactor->redact($value);
        }

        if (! is_array($value)) {
            return $value;
        }

        foreach ($value as $key => $item) {
            $value[$key] = $this->redactValue($item);
        }

        return $value;
    }
}
