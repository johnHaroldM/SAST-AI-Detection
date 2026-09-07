<?php

namespace App\Services;

use App\Models\AiAssessment;
use App\Models\Finding;
use App\Services\AI\SecretRedactor;
use Illuminate\Filesystem\FilesystemAdapter;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use InvalidArgumentException;
use JsonException;
use RuntimeException;
use Throwable;

/**
 * Writes a deterministic, private snapshot of the data surrounding Rubix.
 *
 * Trusted labels are kept separate from weak or unattributed labels, and the
 * validation file contains only the independent project/commit partition
 * selected by RubixTriageService. The export is intentionally read-only: a
 * reviewer may fill review_queue.csv, but importing that review is a separate
 * explicit operation.
 */
final class RubixTrainingDatasetExporter
{
    public const SCHEMA_VERSION = '1.0';

    /** @var list<string> */
    private const TRUSTED_SOURCES = ['human', 'benchmark', 'import'];

    /** @var list<string> */
    private const DATA_FILES = [
        'train.jsonl',
        'validation.jsonl',
        'review_queue.jsonl',
        'review_queue.csv',
        'quarantine.jsonl',
    ];

    public function __construct(
        private readonly RubixTriageService $triage,
        private readonly SecretRedactor $redactor = new SecretRedactor,
    ) {}

    /**
     * @return array<string, mixed> The manifest written beside the dataset.
     */
    public function export(
        ?string $outputDirectory = null,
        ?int $validationPercent = null,
        int $reviewLimit = 500,
    ): array {
        $validationPercent ??= (int) config('sast.training.validation_percent', 20);
        $this->validateOptions($validationPercent, $reviewLimit);

        $directory = $this->outputDirectory($outputDirectory);
        $disk = Storage::disk('local');
        $this->assertNewDirectory($disk, $directory);

        $snapshot = $this->triage->trainingDatasetSnapshot($validationPercent);
        $featureOrder = $this->triage->featureOrder();

        [$train, $trainQuarantine] = $this->routeSnapshotRows(
            $this->snapshotRows($snapshot, 'train'),
            'train',
            $featureOrder,
        );
        [$validation, $validationQuarantine] = $this->routeSnapshotRows(
            $this->snapshotRows($snapshot, 'validation'),
            'validation',
            $featureOrder,
        );

        $snapshotRows = [
            ...$this->snapshotRows($snapshot, 'train'),
            ...$this->snapshotRows($snapshot, 'validation'),
        ];
        $ambiguousFeatureHashes = $this->ambiguousFeatureHashes($snapshotRows);
        $truePositiveRuleCounts = $this->truePositiveRuleCounts($snapshotRows);
        $untrustedQuarantine = $this->untrustedLabelQuarantine($featureOrder, $ambiguousFeatureHashes);
        $quarantine = [
            ...$trainQuarantine,
            ...$validationQuarantine,
            ...$untrustedQuarantine,
        ];

        usort($quarantine, static fn (array $left, array $right): int => [
            $left['quarantine_reason'],
            $left['fingerprint_sha256'],
            $left['label'],
            $left['finding_id'],
        ] <=> [
            $right['quarantine_reason'],
            $right['fingerprint_sha256'],
            $right['label'],
            $right['finding_id'],
        ]);

        $review = $this->reviewQueue(
            $reviewLimit,
            $featureOrder,
            $ambiguousFeatureHashes,
            $truePositiveRuleCounts,
        );
        $records = [
            'train.jsonl' => $train,
            'validation.jsonl' => $validation,
            'review_queue.jsonl' => $review['rows'],
            'quarantine.jsonl' => $quarantine,
        ];
        $payloads = [
            'train.jsonl' => $this->jsonl($train),
            'validation.jsonl' => $this->jsonl($validation),
            'review_queue.jsonl' => $this->jsonl($review['rows']),
            'review_queue.csv' => $this->reviewCsv($review['rows']),
            'quarantine.jsonl' => $this->jsonl($quarantine),
        ];
        $fileMetadata = $this->fileMetadata($directory, $payloads, $records, count($review['rows']));
        $statistics = $snapshot['statistics'];

        $manifest = $this->manifest(
            directory: $directory,
            validationPercent: $validationPercent,
            featureOrder: $featureOrder,
            datasetFingerprint: $snapshot['dataset_fingerprint'],
            train: $train,
            validation: $validation,
            quarantine: $quarantine,
            review: $review,
            statistics: $statistics,
            files: $fileMetadata,
        );

        $payloads['manifest.json'] = $this->encode($manifest, pretty: true)."\n";
        $this->writeNewDirectory($disk, $directory, $payloads);

        return $manifest;
    }

    private function validateOptions(int $validationPercent, int $reviewLimit): void
    {
        if ($validationPercent < 1 || $validationPercent > 50) {
            throw new InvalidArgumentException('Validation percent must be between 1 and 50.');
        }

        if ($reviewLimit < 0) {
            throw new InvalidArgumentException('Review limit must be zero or greater.');
        }
    }

    private function outputDirectory(?string $outputDirectory): string
    {
        if ($outputDirectory === null || trim($outputDirectory) === '') {
            return 'rubix-training/'.now()->format('Ymd_His_u');
        }

        $normalized = str_replace('\\', '/', trim($outputDirectory));

        if (
            str_contains($normalized, "\0")
            || preg_match('#^(?:/|[A-Za-z]:/|//)#', $normalized) === 1
            || collect(explode('/', $normalized))->contains(
                static fn (string $segment): bool => $segment === '..' || $segment === '.',
            )
        ) {
            throw new InvalidArgumentException(
                'Output must be a relative local-storage directory without traversal segments.'
            );
        }

        return rtrim($normalized, '/');
    }

    private function assertNewDirectory(FilesystemAdapter $disk, string $directory): void
    {
        if ($disk->exists($directory) || $disk->directoryExists($directory)) {
            throw new RuntimeException(
                "Rubix training export directory [{$directory}] already exists; choose a new output directory."
            );
        }
    }

    /**
     * @param  array<string, mixed>  $snapshot
     * @return list<array<string, mixed>>
     */
    private function snapshotRows(array $snapshot, string $partition): array
    {
        $rows = $snapshot[$partition] ?? null;

        if (! is_array($rows)) {
            throw new RuntimeException("Rubix dataset snapshot is missing the [{$partition}] partition.");
        }

        return array_values(array_filter($rows, 'is_array'));
    }

    /**
     * @param  list<array<string, mixed>>  $rows
     * @param  list<string>  $featureOrder
     * @return array{0:list<array<string, mixed>>,1:list<array<string, mixed>>}
     */
    private function routeSnapshotRows(array $rows, string $split, array $featureOrder): array
    {
        $trusted = [];
        $quarantine = [];

        foreach ($rows as $row) {
            $source = $this->labelSource($row['label_source'] ?? null);

            if (in_array($source, self::TRUSTED_SOURCES, true)) {
                $trusted[] = $this->labeledRecord($row, $split, $source, true, $featureOrder);

                continue;
            }

            $reason = $source === null || $source === 'unattributed'
                ? 'unattributed_label'
                : ($source === 'ai_pseudo' ? 'ai_pseudo_label' : 'untrusted_label_source');
            $record = $this->labeledRecord($row, 'quarantine', $source, false, $featureOrder);
            $record['candidate_split'] = $split;
            $record['quarantine_reason'] = $reason;
            $quarantine[] = $record;
        }

        return [$trusted, $quarantine];
    }

    /**
     * @param  array<string, mixed>  $row
     * @param  list<string>  $featureOrder
     * @return array<string, mixed>
     */
    private function labeledRecord(
        array $row,
        string $split,
        ?string $labelSource,
        bool $trusted,
        array $featureOrder,
    ): array {
        $sample = $this->sample($row['sample'] ?? null, $featureOrder);
        $groupKey = (string) ($row['group_key'] ?? '');
        $fingerprint = (string) ($row['fingerprint'] ?? $row['fingerprint_sha256'] ?? '');

        if ($fingerprint === '') {
            throw new RuntimeException('Rubix dataset row is missing its finding fingerprint.');
        }

        return [
            'schema_version' => self::SCHEMA_VERSION,
            'finding_id' => (int) ($row['finding_id'] ?? $row['finding'] ?? 0),
            'project_id' => (int) ($row['project_id'] ?? $row['project'] ?? 0),
            'scan_id' => (int) ($row['scan_id'] ?? $row['scan'] ?? 0),
            'scanner_source' => (string) ($row['scanner_source'] ?? $row['scan_source'] ?? $row['source'] ?? ''),
            'commit_sha' => (string) ($row['commit_sha'] ?? $row['commit'] ?? ''),
            'split' => $split,
            'fingerprint_sha256' => $fingerprint,
            'group_sha256' => (string) ($row['group_sha256'] ?? hash('sha256', $groupKey)),
            'rule_id' => (string) ($row['rule_id'] ?? $row['rule'] ?? ''),
            'cwe_id' => isset($row['cwe_id']) ? (int) $row['cwe_id'] : null,
            'file_path' => (string) ($row['file_path'] ?? $row['path'] ?? ''),
            'line_number' => (int) ($row['line_number'] ?? $row['line'] ?? 0),
            'severity' => (string) ($row['severity'] ?? ''),
            'label' => (string) ($row['label'] ?? ''),
            'label_source' => $labelSource,
            'trusted_for_certification' => $trusted,
            'features' => $this->features($sample, $featureOrder),
            'sample' => $sample,
            'feature_sha256' => (string) ($row['feature_sha256'] ?? $this->featureHash($sample)),
            'ambiguous_feature' => (bool) ($row['ambiguous_feature'] ?? false),
            'duplicate_count' => max(1, (int) ($row['duplicate_count'] ?? 1)),
        ];
    }

    /**
     * @param  list<string>  $featureOrder
     * @param  array<string, true>  $knownAmbiguous
     * @return list<array<string, mixed>>
     */
    private function untrustedLabelQuarantine(array $featureOrder, array $knownAmbiguous): array
    {
        $findings = Finding::query()
            ->whereNotNull('final_label')
            ->whereNotNull('feature_vector')
            ->whereDoesntHave('feedback', fn ($query) => $query
                ->whereIn('source', self::TRUSTED_SOURCES)
                ->where('training_eligible', true)
                ->whereColumn('triage_feedback.corrected_label', 'findings.final_label'))
            ->with([
                'feedback:id,finding_id,corrected_label,source,training_eligible,training_exclusion_reason',
                'scan:id,project_id,source,commit_sha',
            ])
            ->orderBy('id')
            ->get();

        /** @var array<string, list<Finding>> $buckets */
        $buckets = [];

        foreach ($findings as $finding) {
            $fingerprint = $this->triage->findingFingerprint($finding);
            $source = $this->labelSource($finding->feedback?->source);
            $bucketKey = implode("\0", [
                $fingerprint,
                (string) $finding->final_label,
                (string) $source,
            ]);
            $buckets[$bucketKey][] = $finding;
        }

        ksort($buckets);
        $records = [];

        foreach ($buckets as $candidates) {
            usort($candidates, fn (Finding $left, Finding $right): int => [
                $this->triage->findingGroupKey($left),
                $left->getKey(),
            ] <=> [
                $this->triage->findingGroupKey($right),
                $right->getKey(),
            ]);

            $finding = $candidates[0];
            $sample = $this->triage->vectorize($finding->feature_vector ?? []);
            $featureHash = $this->featureHash($sample);
            $feedback = $finding->feedback;
            $source = $this->labelSource($feedback?->source);
            $record = $this->findingRecord(
                $finding,
                split: 'quarantine',
                label: (string) $finding->final_label,
                labelSource: $source,
                trusted: false,
                sample: $sample,
                featureOrder: $featureOrder,
                ambiguous: isset($knownAmbiguous[$featureHash]),
                duplicateCount: count($candidates),
            );
            $record['quarantine_reason'] = match (true) {
                $feedback === null => 'unattributed_label',
                $feedback->training_eligible === false => 'label_quality_review',
                $source === 'ai_pseudo' => 'ai_pseudo_label',
                ! in_array($source, self::TRUSTED_SOURCES, true) => 'untrusted_label_source',
                default => 'inconsistent_label',
            };
            $records[] = $record;
        }

        return $records;
    }

    /**
     * @param  list<string>  $featureOrder
     * @param  array<string, true>  $knownAmbiguous
     * @param  array<string, int>  $truePositiveRuleCounts
     * @return array{rows:list<array<string,mixed>>,available:int,candidates:int,excluded_duplicates:int,exported:int,truncated:int}
     */
    private function reviewQueue(
        int $limit,
        array $featureOrder,
        array $knownAmbiguous,
        array $truePositiveRuleCounts,
    ): array {
        $findings = Finding::query()
            ->whereNull('final_label')
            ->whereNotNull('feature_vector')
            ->with([
                'scan:id,project_id,source,commit_sha',
                'aiAssessments' => fn ($query) => $query
                    ->whereNotNull('completed_at')
                    ->orderBy('reviewer')
                    ->orderByDesc('completed_at')
                    ->orderByDesc('id'),
            ])
            ->orderBy('id')
            ->get();

        /** @var array<string, list<Finding>> $buckets */
        $buckets = [];

        foreach ($findings as $finding) {
            $buckets[$this->triage->findingFingerprint($finding)][] = $finding;
        }

        ksort($buckets);
        $rows = [];

        foreach ($buckets as $candidates) {
            usort($candidates, fn (Finding $left, Finding $right): int => [
                $this->triage->findingGroupKey($left),
                $this->encode($this->triage->vectorize($left->feature_vector ?? [])),
                $left->getKey(),
            ] <=> [
                $this->triage->findingGroupKey($right),
                $this->encode($this->triage->vectorize($right->feature_vector ?? [])),
                $right->getKey(),
            ]);

            $finding = $candidates[0];
            $sample = $this->triage->vectorize($finding->feature_vector ?? []);
            $featureHash = $this->featureHash($sample);
            $assessments = $this->advisoryAssessments($finding);
            [$priority, $priorityReasons] = $this->reviewPriority(
                $finding,
                $assessments,
                count($candidates),
                (int) ($truePositiveRuleCounts[(string) $finding->rule_id] ?? 0),
            );
            $record = $this->findingRecord(
                $finding,
                split: 'review',
                label: null,
                labelSource: null,
                trusted: false,
                sample: $sample,
                featureOrder: $featureOrder,
                ambiguous: isset($knownAmbiguous[$featureHash]),
                duplicateCount: count($candidates),
            );
            $message = $this->redactor->redact((string) $finding->message);
            $snippet = trim((string) $finding->raw_snippet);
            $sourceExcerpt = $this->redactor->redact($snippet !== '' ? $snippet : $message);

            $record['label'] = null;
            $record['human_label'] = '';
            $record['message'] = $message;
            $record['source_excerpt'] = Str::limit($sourceExcerpt, 4000, '...');
            $record['rubix_advisory_probability'] = $finding->tp_probability;
            $record['priority_score'] = $priority;
            $record['priority_reasons'] = $priorityReasons;
            $record['advisory_assessments'] = $assessments;
            $rows[] = $record;
        }

        usort($rows, static fn (array $left, array $right): int => [
            -$left['priority_score'],
            $left['fingerprint_sha256'],
            $left['finding_id'],
        ] <=> [
            -$right['priority_score'],
            $right['fingerprint_sha256'],
            $right['finding_id'],
        ]);

        $available = count($rows);
        $exported = $limit === 0 ? $available : min($available, $limit);

        return [
            'rows' => array_slice($rows, 0, $exported),
            'available' => $available,
            'candidates' => $findings->count(),
            'excluded_duplicates' => $findings->count() - $available,
            'exported' => $exported,
            'truncated' => $available - $exported,
        ];
    }

    /**
     * @param  list<array<string, mixed>>  $assessments
     * @return array{0:int,1:list<string>}
     */
    private function reviewPriority(
        Finding $finding,
        array $assessments,
        int $duplicateCount,
        int $trustedTruePositivesForRule,
    ): array {
        $severityScore = match (strtoupper((string) $finding->severity)) {
            'CRITICAL' => 40,
            'HIGH' => 30,
            'MEDIUM' => 20,
            default => 10,
        };
        $score = $severityScore;
        $reasons = ['severity_'.strtolower((string) $finding->severity)];
        $ruleId = strtolower((string) $finding->rule_id);
        $snippet = strtolower((string) $finding->raw_snippet);

        if ($trustedTruePositivesForRule === 0) {
            $score += 30;
            $reasons[] = 'no_trusted_tp_for_rule';
        } elseif ($trustedTruePositivesForRule <= 2) {
            $score += 20;
            $reasons[] = 'scarce_trusted_tp_for_rule';
        } elseif ($trustedTruePositivesForRule <= 5) {
            $score += 10;
            $reasons[] = 'limited_trusted_tp_for_rule';
        }

        if (str_contains($ruleId, 'command-injection')) {
            $score += 25;
            $reasons[] = 'command_injection_priority';
        } elseif (str_contains($ruleId, 'path-traversal')) {
            $score += 15;
            $reasons[] = 'path_traversal_priority';
        }

        if (
            str_contains($ruleId, 'path-traversal')
            && preg_match('/\b(?:include|require|file_get_contents|readfile|fopen)\b/', $snippet) === 1
        ) {
            $score += 10;
            $reasons[] = 'dynamic_file_sink_candidate';
        }

        if (trim($snippet) !== '') {
            $score += 5;
            $reasons[] = 'source_excerpt_present';
        }

        if ($finding->tp_probability !== null) {
            $score += (int) round(max(0.0, min(1.0, (float) $finding->tp_probability)) * 5);
            $reasons[] = 'rubix_advisory_tiebreaker';
        }

        $classificationScores = [
            'confirmed_tp' => 15,
            'likely_tp' => 12,
            'needs_validation' => 6,
            'likely_fp' => 3,
            'confirmed_fp' => 0,
        ];
        $assessmentScore = 0;
        $advisoryLabels = [];

        foreach ($assessments as $assessment) {
            $classification = (string) ($assessment['classification'] ?? '');
            $assessmentScore = max($assessmentScore, $classificationScores[$classification] ?? 0);

            if (in_array($classification, ['confirmed_tp', 'likely_tp'], true)) {
                $advisoryLabels['true_positive'] = true;
            } elseif (in_array($classification, ['confirmed_fp', 'likely_fp'], true)) {
                $advisoryLabels['false_positive'] = true;
            }

            if ($classification === 'needs_validation') {
                $reasons[] = 'ai_needs_validation';
            }
        }

        if ($assessmentScore > 0) {
            $score += $assessmentScore;
            $reasons[] = 'ai_advisory_signal';
        }

        if (count($advisoryLabels) > 1) {
            $score += 20;
            $reasons[] = 'ai_disagreement';
        }

        if ($duplicateCount > 1) {
            $score += min(10, $duplicateCount - 1);
            $reasons[] = 'repeated_finding';
        }

        return [$score, array_values(array_unique($reasons))];
    }

    /** @return list<array<string, mixed>> */
    private function advisoryAssessments(Finding $finding): array
    {
        /** @var array<string, AiAssessment> $latest */
        $latest = [];

        foreach ($finding->aiAssessments as $assessment) {
            $reviewer = strtolower(trim((string) $assessment->reviewer));

            if ($reviewer === '' || isset($latest[$reviewer])) {
                continue;
            }

            $latest[$reviewer] = $assessment;
        }

        ksort($latest);

        return array_values(array_map(fn (AiAssessment $assessment): array => [
            'advisory_only' => true,
            'assessment_id' => (int) $assessment->getKey(),
            'reviewer' => (string) $assessment->reviewer,
            'model' => (string) $assessment->model,
            'model_version' => $assessment->model_version,
            'classification' => (string) $assessment->classification,
            'confidence' => $assessment->confidence,
            'attacker_controlled' => $assessment->attacker_controlled,
            'sink_reachable' => $assessment->sink_reachable,
            'mitigation_detected' => $assessment->mitigation_detected,
            'reasoning_summary' => $assessment->reasoning_summary === null
                ? null
                : $this->redactor->redact($assessment->reasoning_summary),
            'completed_at' => $assessment->completed_at?->toIso8601String(),
        ], $latest));
    }

    /**
     * @param  list<mixed>  $sample
     * @param  list<string>  $featureOrder
     * @return array<string, mixed>
     */
    private function findingRecord(
        Finding $finding,
        string $split,
        ?string $label,
        ?string $labelSource,
        bool $trusted,
        array $sample,
        array $featureOrder,
        bool $ambiguous,
        int $duplicateCount,
    ): array {
        $scan = $finding->scan;

        if ($scan === null) {
            throw new RuntimeException("Finding [{$finding->getKey()}] has no scan and cannot be exported.");
        }

        return [
            'schema_version' => self::SCHEMA_VERSION,
            'finding_id' => (int) $finding->getKey(),
            'project_id' => (int) $scan->project_id,
            'scan_id' => (int) $scan->getKey(),
            'scanner_source' => (string) $scan->source,
            'commit_sha' => (string) $scan->commit_sha,
            'split' => $split,
            'fingerprint_sha256' => $this->triage->findingFingerprint($finding),
            'group_sha256' => hash('sha256', $this->triage->findingGroupKey($finding)),
            'rule_id' => (string) $finding->rule_id,
            'cwe_id' => $finding->cwe_id === null ? null : (int) $finding->cwe_id,
            'file_path' => (string) $finding->file_path,
            'line_number' => (int) $finding->line_number,
            'severity' => (string) $finding->severity,
            'label' => $label,
            'label_source' => $labelSource,
            'trusted_for_certification' => $trusted,
            'features' => $this->features($sample, $featureOrder),
            'sample' => $sample,
            'feature_sha256' => $this->featureHash($sample),
            'ambiguous_feature' => $ambiguous,
            'duplicate_count' => max(1, $duplicateCount),
        ];
    }

    /**
     * @param  list<string>  $featureOrder
     * @return list<mixed>
     */
    private function sample(mixed $value, array $featureOrder): array
    {
        if (! is_array($value) || count($value) !== count($featureOrder)) {
            throw new RuntimeException('Rubix dataset row has an invalid ordered feature sample.');
        }

        return array_values($value);
    }

    /**
     * @param  list<mixed>  $sample
     * @param  list<string>  $featureOrder
     * @return array<string, mixed>
     */
    private function features(array $sample, array $featureOrder): array
    {
        return array_combine($featureOrder, $sample);
    }

    /** @param list<mixed> $sample */
    private function featureHash(array $sample): string
    {
        return hash('sha256', $this->encode($sample));
    }

    private function labelSource(mixed $source): ?string
    {
        if (! is_string($source) || trim($source) === '') {
            return null;
        }

        return strtolower(trim($source));
    }

    /**
     * Count independent, deduplicated TP examples per rule. The review queue
     * uses this only for acquisition priority; it never turns the result into
     * a proposed ground-truth label.
     *
     * @param  list<array<string, mixed>>  $rows
     * @return array<string, int>
     */
    private function truePositiveRuleCounts(array $rows): array
    {
        $counts = [];

        foreach ($rows as $row) {
            $source = $this->labelSource($row['label_source'] ?? null);

            if (
                ($row['label'] ?? null) !== 'true_positive'
                || ! in_array($source, self::TRUSTED_SOURCES, true)
            ) {
                continue;
            }

            $ruleId = (string) ($row['rule_id'] ?? '');

            if ($ruleId !== '') {
                $counts[$ruleId] = ($counts[$ruleId] ?? 0) + 1;
            }
        }

        ksort($counts);

        return $counts;
    }

    /**
     * @param  list<array<string, mixed>>  $rows
     * @return array<string, true>
     */
    private function ambiguousFeatureHashes(array $rows): array
    {
        $hashes = [];

        foreach ($rows as $row) {
            if (($row['ambiguous_feature'] ?? false) !== true) {
                continue;
            }

            $hash = (string) ($row['feature_sha256'] ?? '');

            if ($hash !== '') {
                $hashes[$hash] = true;
            }
        }

        return $hashes;
    }

    /** @param list<array<string, mixed>> $records */
    private function jsonl(array $records): string
    {
        $payload = '';

        foreach ($records as $record) {
            $payload .= $this->encode($record)."\n";
        }

        return $payload;
    }

    /** @param list<array<string, mixed>> $records */
    private function reviewCsv(array $records): string
    {
        $stream = fopen('php://temp', 'w+');

        if ($stream === false) {
            throw new RuntimeException('Unable to create the in-memory review queue CSV.');
        }

        $headers = [
            'priority_score',
            'finding_id',
            'project_id',
            'scan_id',
            'scanner_source',
            'commit_sha',
            'fingerprint_sha256',
            'group_sha256',
            'rule_id',
            'cwe_id',
            'file_path',
            'line_number',
            'severity',
            'message',
            'source_excerpt',
            'rubix_advisory_probability',
            'advisory_summary',
            'human_label',
        ];

        fputcsv($stream, $headers, ',', '"', '');

        foreach ($records as $record) {
            $advisorySummary = implode(' | ', array_map(
                static function (array $assessment): string {
                    $confidence = $assessment['confidence'] === null
                        ? 'n/a'
                        : number_format((float) $assessment['confidence'], 4, '.', '');

                    return sprintf(
                        '%s:%s(%s)',
                        $assessment['reviewer'],
                        $assessment['classification'],
                        $confidence,
                    );
                },
                $record['advisory_assessments'],
            ));

            $values = [
                $record['priority_score'],
                $record['finding_id'],
                $record['project_id'],
                $record['scan_id'],
                $record['scanner_source'],
                $record['commit_sha'],
                $record['fingerprint_sha256'],
                $record['group_sha256'],
                $record['rule_id'],
                $record['cwe_id'],
                $record['file_path'],
                $record['line_number'],
                $record['severity'],
                $record['message'],
                $record['source_excerpt'],
                $record['rubix_advisory_probability'],
                $advisorySummary,
                '',
            ];

            fputcsv(
                $stream,
                array_map(fn (mixed $value): mixed => $this->safeCsvCell($value), $values),
                ',',
                '"',
                '',
            );
        }

        rewind($stream);
        $payload = stream_get_contents($stream);
        fclose($stream);

        if ($payload === false) {
            throw new RuntimeException('Unable to read the in-memory review queue CSV.');
        }

        return $payload;
    }

    private function safeCsvCell(mixed $value): mixed
    {
        if (! is_string($value) || preg_match('/^\s*[=+\-@]/u', $value) !== 1) {
            return $value;
        }

        return "'".$value;
    }

    /**
     * @param  array<string, string>  $payloads
     * @param  array<string, list<array<string, mixed>>>  $jsonRecords
     * @return array<string, array{path:string,records:int,bytes:int,sha256:string}>
     */
    private function fileMetadata(
        string $directory,
        array $payloads,
        array $jsonRecords,
        int $reviewCount,
    ): array {
        $files = [];

        foreach (self::DATA_FILES as $filename) {
            $payload = $payloads[$filename];
            $files[$filename] = [
                'path' => $directory.'/'.$filename,
                'records' => $filename === 'review_queue.csv'
                    ? $reviewCount
                    : count($jsonRecords[$filename] ?? []),
                'bytes' => strlen($payload),
                'sha256' => hash('sha256', $payload),
            ];
        }

        return $files;
    }

    /**
     * @param  list<string>  $featureOrder
     * @param  list<array<string, mixed>>  $train
     * @param  list<array<string, mixed>>  $validation
     * @param  list<array<string, mixed>>  $quarantine
     * @param  array{rows:list<array<string,mixed>>,available:int,candidates:int,excluded_duplicates:int,exported:int,truncated:int}  $review
     * @param  array<string, mixed>  $statistics
     * @param  array<string, array{path:string,records:int,bytes:int,sha256:string}>  $files
     * @return array<string, mixed>
     */
    private function manifest(
        string $directory,
        int $validationPercent,
        array $featureOrder,
        string $datasetFingerprint,
        array $train,
        array $validation,
        array $quarantine,
        array $review,
        array $statistics,
        array $files,
    ): array {
        return [
            'schema_version' => self::SCHEMA_VERSION,
            'generated_at' => now()->toIso8601String(),
            'output_directory' => $directory,
            'dataset_fingerprint' => $datasetFingerprint,
            'feature_order' => $featureOrder,
            'split_strategy' => 'project_commit_hash_v1',
            'validation_percent' => $validationPercent,
            'split' => [
                'strategy' => 'project_commit_hash_v1',
                'validation_percent' => $validationPercent,
                'description' => 'sha256(project_id + NUL + lowercase(commit_sha)) modulo 100',
            ],
            'trusted_sources' => self::TRUSTED_SOURCES,
            'record_count' => count($train) + count($validation),
            'counts' => [
                'train' => count($train),
                'validation' => count($validation),
                'review_queue' => count($review['rows']),
                'quarantine' => count($quarantine),
            ],
            'labels' => [
                'train' => $this->labelCounts($train),
                'validation' => $this->labelCounts($validation),
                'quarantine' => $this->labelCounts($quarantine),
            ],
            'sources' => [
                'train' => $this->sourceCounts($train),
                'validation' => $this->sourceCounts($validation),
                'quarantine' => $this->sourceCounts($quarantine),
            ],
            'review_queue' => [
                'candidates' => $review['candidates'],
                'available_after_deduplication' => $review['available'],
                'excluded_duplicates' => $review['excluded_duplicates'],
                'exported' => $review['exported'],
                'truncated' => $review['truncated'],
                'priority_strategy' => 'underrepresented rule families + command/path sinks + severity + source availability + small advisory tie-breakers',
            ],
            'quality_gates' => [
                'tp_flag_threshold' => (float) config('sast.training.tp_flag_threshold', 0.8),
                'min_deploy_precision' => (float) config('sast.training.min_deploy_precision', 0.8),
                'min_deploy_flags' => (int) config('sast.training.min_deploy_flags', 5),
                'min_validation_true_positives' => (int) config('sast.training.min_validation_true_positives', 5),
                'min_validation_tp_groups' => (int) config('sast.training.min_validation_tp_groups', 2),
            ],
            'snapshot_statistics' => $statistics,
            'warnings' => $this->warnings($train, $validation, $quarantine, $review, $statistics),
            'privacy' => [
                'disk' => 'local-private',
                'source_text' => 'Only the human review queue contains source excerpts; messages and excerpts are secret-redacted.',
                'ai_outputs' => 'AI assessments are advisory metadata and are never exported as ground-truth labels.',
                'csv_formula_protection' => true,
            ],
            'labeling_guidance' => [
                'allowed_human_labels' => ['true_positive', 'false_positive'],
                'blank_means' => 'unreviewed',
                'certification_rule' => 'Only independently verified human, benchmark, or import labels may enter certification partitions.',
                'feature_gap' => 'Opposite labels sharing all nine features require richer source/dataflow features, not duplicated labels.',
            ],
            'files' => $files,
        ];
    }

    /**
     * @param  list<array<string, mixed>>  $records
     * @return array{true_positive:int,false_positive:int}
     */
    private function labelCounts(array $records): array
    {
        $counts = ['true_positive' => 0, 'false_positive' => 0];

        foreach ($records as $record) {
            $label = $record['label'] ?? null;

            if (is_string($label) && array_key_exists($label, $counts)) {
                $counts[$label]++;
            }
        }

        return $counts;
    }

    /**
     * @param  list<array<string, mixed>>  $records
     * @return array<string, int>
     */
    private function sourceCounts(array $records): array
    {
        $counts = [];

        foreach ($records as $record) {
            $source = $record['label_source'] ?? null;
            $key = is_string($source) && $source !== '' ? $source : 'unattributed';
            $counts[$key] = ($counts[$key] ?? 0) + 1;
        }

        ksort($counts);

        return $counts;
    }

    /**
     * @param  list<array<string, mixed>>  $train
     * @param  list<array<string, mixed>>  $validation
     * @param  list<array<string, mixed>>  $quarantine
     * @param  array{rows:list<array<string,mixed>>,available:int,candidates:int,excluded_duplicates:int,exported:int,truncated:int}  $review
     * @param  array<string, mixed>  $statistics
     * @return list<string>
     */
    private function warnings(
        array $train,
        array $validation,
        array $quarantine,
        array $review,
        array $statistics,
    ): array {
        $warnings = [];
        $trainLabels = $this->labelCounts($train);
        $validationLabels = $this->labelCounts($validation);
        $minimumPositiveGroups = (int) config('sast.training.min_validation_tp_groups', 2);
        $validationStatistics = is_array($statistics['validation'] ?? null)
            ? $statistics['validation']
            : [];

        if ($trainLabels['true_positive'] === 0 || $trainLabels['false_positive'] === 0) {
            $warnings[] = 'The trusted training partition does not contain both labels.';
        }

        if ($validationLabels['true_positive'] === 0 || $validationLabels['false_positive'] === 0) {
            $warnings[] = 'The trusted validation partition does not contain both labels.';
        }

        if ($validationLabels['true_positive'] < (int) config('sast.training.min_validation_true_positives', 5)) {
            $warnings[] = 'The validation partition has fewer true positives than the deployment support gate requires.';
        }

        if ((int) ($validationStatistics['true_positive_groups'] ?? 0) < $minimumPositiveGroups) {
            $warnings[] = 'The validation partition has true positives from fewer independent project groups than the deployment gate requires.';
        }

        if (
            $trainLabels['true_positive'] > 0
            && $trainLabels['false_positive'] / $trainLabels['true_positive'] >= 5
        ) {
            $warnings[] = sprintf(
                'The trusted training partition is imbalanced at %.1f false positives per true positive.',
                $trainLabels['false_positive'] / $trainLabels['true_positive'],
            );
        }

        if ($quarantine !== []) {
            $warnings[] = count($quarantine).' weak or unattributed labeled record(s) were quarantined and cannot certify Rubix.';
        }

        if ($review['truncated'] > 0) {
            $warnings[] = $review['truncated'].' review candidate(s) were omitted by the review limit.';
        }

        if ((int) ($statistics['ambiguous_feature_rows'] ?? 0) > 0) {
            $warnings[] = (int) $statistics['ambiguous_feature_rows'].' labeled row(s) share features with the opposite label.';
        }

        if ((int) ($statistics['excluded_conflicts'] ?? 0) > 0) {
            $warnings[] = (int) $statistics['excluded_conflicts'].' exact finding row(s) were excluded because their labels conflict.';
        }

        if ((int) ($statistics['excluded_inconsistent_labels'] ?? 0) > 0) {
            $warnings[] = (int) $statistics['excluded_inconsistent_labels'].' row(s) were excluded because finding and feedback labels disagree.';
        }

        $snapshotWarnings = $statistics['warnings'] ?? [];

        if (is_array($snapshotWarnings)) {
            foreach ($snapshotWarnings as $warning) {
                if (is_string($warning) && trim($warning) !== '') {
                    $warnings[] = trim($warning);
                }
            }
        }

        return array_values(array_unique($warnings));
    }

    /**
     * @param  array<string, string>  $payloads
     */
    private function writeNewDirectory(FilesystemAdapter $disk, string $directory, array $payloads): void
    {
        if (! $disk->makeDirectory($directory)) {
            throw new RuntimeException("Unable to create Rubix training export directory [{$directory}].");
        }

        try {
            foreach ($payloads as $filename => $payload) {
                $path = $directory.'/'.$filename;

                if (! $disk->put($path, $payload)) {
                    throw new RuntimeException("Unable to write Rubix training dataset file [{$path}].");
                }
            }
        } catch (Throwable $exception) {
            $disk->deleteDirectory($directory);

            if ($exception instanceof RuntimeException) {
                throw $exception;
            }

            throw new RuntimeException('Unable to write the Rubix training dataset.', 0, $exception);
        }
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

        try {
            return json_encode($value, $flags);
        } catch (JsonException $exception) {
            throw new RuntimeException('Unable to encode the Rubix training dataset.', 0, $exception);
        }
    }
}
