<?php

use App\Models\AiAssessment;
use App\Models\AiAssessmentFeedback;
use App\Models\Finding;
use App\Models\FindingAiContext;
use App\Models\Project;
use App\Models\Scan;
use App\Models\TriageFeedback;
use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;

function exportDatasetFinding(
    Scan $scan,
    string $contextHash,
    ?string $finalLabel = null,
    string $context = '{"source_context":{"code":"safe"}}',
): Finding {
    $finding = Finding::factory()->for($scan)->create([
        'final_label' => $finalLabel,
        'status' => $finalLabel === null ? 'pending' : 'triaged',
    ]);

    FindingAiContext::create([
        'finding_id' => $finding->id,
        'source_commit' => $scan->commit_sha,
        'context_hash' => $contextHash,
        'metadata' => ['format_version' => 'test-v1'],
        'context' => $context,
    ]);

    return $finding;
}

function exportDatasetAssessment(
    Finding $finding,
    string $reviewer,
    string $classification = 'likely_tp',
    ?DateTimeInterface $completedAt = null,
): AiAssessment {
    return AiAssessment::create([
        'finding_id' => $finding->id,
        'reviewer' => $reviewer,
        'model' => 'test-'.$reviewer,
        'model_version' => 'q4-test',
        'classification' => $classification,
        'confidence' => 0.82,
        'attacker_controlled' => true,
        'sink_reachable' => true,
        'mitigation_detected' => false,
        'preconditions' => ['A route reaches the handler.'],
        'supporting_evidence' => ['User input reaches the sink.'],
        'contradicting_evidence' => [],
        'missing_evidence' => ['Runtime configuration is unavailable.'],
        'remediation' => ['Use a parameterized API.'],
        'reasoning_summary' => 'The supplied evidence supports the scanner finding.',
        'prompt_version' => $reviewer.'-v2',
        'context_hash' => $finding->aiContext->context_hash,
        'usage' => ['prompt_eval_count' => 100],
        'raw_response' => ['must_not' => 'be exported'],
        'completed_at' => $completedAt ?? now(),
    ]);
}

/** @return list<array<string, mixed>> */
function exportDatasetRecords(string $path): array
{
    $payload = Storage::disk('local')->get($path);

    if ($payload === '') {
        return [];
    }

    return array_map(
        static fn (string $line): array => json_decode($line, true, flags: JSON_THROW_ON_ERROR),
        explode("\n", rtrim($payload, "\n")),
    );
}

test('export includes only trusted feedback and redacts training input', function () {
    Storage::fake('local');

    $user = User::factory()->create();
    $scan = Scan::factory()->complete()->create([
        'commit_sha' => str_repeat('a', 40),
    ]);

    $explicitFinding = exportDatasetFinding(
        $scan,
        hash('sha256', 'explicit-context'),
        context: '{"code":"$api_key = \"abcdefghijklmnop\";"}',
    );
    $explicitAssessment = exportDatasetAssessment($explicitFinding, 'atake');
    AiAssessmentFeedback::create([
        'assessment_id' => $explicitAssessment->id,
        'user_id' => $user->id,
        'verdict' => 'incorrect',
        'corrected_classification' => 'confirmed_fp',
        'reason_codes' => ['missed_sanitizer'],
        'notes' => 'The framework sanitizer blocks this flow.',
        'reviewed_at' => now(),
    ]);

    $humanFinding = exportDatasetFinding(
        $scan,
        hash('sha256', 'human-context'),
        'true_positive',
    );
    TriageFeedback::create([
        'finding_id' => $humanFinding->id,
        'user_id' => $user->id,
        'original_prediction' => 'false_positive',
        'original_probability' => 0.2,
        'corrected_label' => 'true_positive',
        'notes' => 'Confirmed manually from the route data flow.',
    ]);
    exportDatasetAssessment($humanFinding, 'depensa', 'likely_fp');

    $pseudoFinding = exportDatasetFinding(
        $scan,
        hash('sha256', 'pseudo-context'),
        'false_positive',
    );
    TriageFeedback::create([
        'finding_id' => $pseudoFinding->id,
        'user_id' => $user->id,
        'original_prediction' => 'true_positive',
        'original_probability' => 0.9,
        'corrected_label' => 'false_positive',
        'source' => 'ai_pseudo',
        'notes' => 'Generated weak label.',
    ]);
    exportDatasetAssessment($pseudoFinding, 'depensa', 'confirmed_fp');

    $legacyPseudoFinding = exportDatasetFinding(
        $scan,
        hash('sha256', 'legacy-pseudo-context'),
        'false_positive',
    );
    TriageFeedback::create([
        'finding_id' => $legacyPseudoFinding->id,
        'user_id' => $user->id,
        'corrected_label' => 'false_positive',
        'notes' => 'AI training label from ATAKE/DEPENSA adjudicator (confirmed_fp, 95% confidence).',
    ]);
    exportDatasetAssessment($legacyPseudoFinding, 'depensa', 'confirmed_fp');

    $literalPseudoFinding = exportDatasetFinding(
        $scan,
        hash('sha256', 'literal-pseudo-context'),
        'false_positive',
    );
    TriageFeedback::create([
        'finding_id' => $literalPseudoFinding->id,
        'user_id' => $user->id,
        'corrected_label' => 'false_positive',
        'notes' => 'AI_PROMOTED: historical weak label.',
    ]);
    exportDatasetAssessment($literalPseudoFinding, 'depensa', 'confirmed_fp');

    $staleContextFinding = exportDatasetFinding(
        $scan,
        hash('sha256', 'old-context'),
    );
    $staleContextAssessment = exportDatasetAssessment($staleContextFinding, 'atake');
    AiAssessmentFeedback::create([
        'assessment_id' => $staleContextAssessment->id,
        'user_id' => $user->id,
        'verdict' => 'correct',
        'reviewed_at' => now(),
    ]);
    $staleContextFinding->aiContext()->update([
        'context_hash' => hash('sha256', 'replacement-context'),
        'context' => '{"code":"replacement"}',
    ]);

    $incompleteFinding = exportDatasetFinding($scan, hash('sha256', 'incomplete-context'));
    $incompleteAssessment = exportDatasetAssessment($incompleteFinding, 'atake');
    $incompleteAssessment->forceFill(['completed_at' => null])->save();
    AiAssessmentFeedback::create([
        'assessment_id' => $incompleteAssessment->id,
        'user_id' => $user->id,
        'verdict' => 'correct',
        'reviewed_at' => now(),
    ]);

    expect(Artisan::call('sast:export-ai-feedback', [
        '--output' => 'anino-training/trusted-test',
    ]))->toBe(Command::SUCCESS);

    $atakeRecords = exportDatasetRecords('anino-training/trusted-test/atake.jsonl');
    $depensaRecords = exportDatasetRecords('anino-training/trusted-test/depensa.jsonl');

    expect($atakeRecords)->toHaveCount(1)
        ->and($depensaRecords)->toHaveCount(1)
        ->and($atakeRecords[0]['assessment_id'])->toBe($explicitAssessment->id)
        ->and($atakeRecords[0]['reference_classification'])->toBe('confirmed_fp')
        ->and($atakeRecords[0]['reference_label'])->toBe('false_positive')
        ->and($atakeRecords[0]['verdict'])->toBe('incorrect')
        ->and($atakeRecords[0]['reason_codes'])->toBe(['missed_sanitizer'])
        ->and($atakeRecords[0]['input_context'])->toContain('[REDACTED:API_KEY_OR_TOKEN]')
        ->and(json_encode($atakeRecords[0]))->not->toContain('abcdefghijklmnop')
        ->and(json_encode($atakeRecords[0]))->not->toContain('raw_response')
        ->and(json_encode($atakeRecords[0]))->not->toContain('must_not')
        ->and(collect($atakeRecords)->pluck('assessment_id'))->not->toContain($staleContextAssessment->id)
        ->and($depensaRecords[0]['finding_id'])->toBe($humanFinding->id)
        ->and($depensaRecords[0]['reference_classification'])->toBe('confirmed_tp')
        ->and($depensaRecords[0]['reference_label'])->toBe('true_positive')
        ->and($depensaRecords[0]['verdict'])->toBeNull()
        ->and($depensaRecords[0]['outcome'])->toBe('false_negative');
});

test('export deduplicates the latest assessment and keeps project commit groups in one split', function () {
    Storage::fake('local');

    $user = User::factory()->create();
    $project = Project::factory()->create();
    $scan = Scan::factory()->for($project)->complete()->create([
        'commit_sha' => str_repeat('b', 40),
    ]);
    $duplicateFinding = exportDatasetFinding($scan, hash('sha256', 'same-context'));

    $older = exportDatasetAssessment(
        $duplicateFinding,
        'atake',
        'likely_tp',
        now()->subHour(),
    );
    AiAssessmentFeedback::create([
        'assessment_id' => $older->id,
        'user_id' => $user->id,
        'verdict' => 'correct',
        'reviewed_at' => now()->subHour(),
    ]);

    $newer = exportDatasetAssessment(
        $duplicateFinding,
        'atake',
        'likely_fp',
        now(),
    );
    AiAssessmentFeedback::create([
        'assessment_id' => $newer->id,
        'user_id' => $user->id,
        'verdict' => 'incorrect',
        'corrected_classification' => 'confirmed_tp',
        'reviewed_at' => now(),
    ]);

    $sameGroupFinding = exportDatasetFinding($scan, hash('sha256', 'other-context'));
    $sameGroupAssessment = exportDatasetAssessment($sameGroupFinding, 'atake');
    AiAssessmentFeedback::create([
        'assessment_id' => $sameGroupAssessment->id,
        'user_id' => $user->id,
        'verdict' => 'correct',
        'reviewed_at' => now(),
    ]);

    $depensa = exportDatasetAssessment($sameGroupFinding, 'depensa');
    AiAssessmentFeedback::create([
        'assessment_id' => $depensa->id,
        'user_id' => $user->id,
        'verdict' => 'correct',
        'reviewed_at' => now(),
    ]);

    expect(Artisan::call('sast:export-ai-feedback', [
        '--reviewer' => 'atake',
        '--output' => 'anino-training/first',
        '--validation-percent' => '50',
    ]))->toBe(Command::SUCCESS);

    $firstRecords = exportDatasetRecords('anino-training/first/atake.jsonl');

    expect($firstRecords)->toHaveCount(2)
        ->and(collect($firstRecords)->pluck('assessment_id')->all())->toContain($newer->id)
        ->and(collect($firstRecords)->pluck('assessment_id')->all())->not->toContain($older->id)
        ->and(collect($firstRecords)->pluck('split')->unique()->count())->toBe(1);

    Storage::disk('local')->assertMissing('anino-training/first/depensa.jsonl');

    expect(Artisan::call('sast:export-ai-feedback', [
        '--reviewer' => 'atake',
        '--output' => 'anino-training/second',
        '--validation-percent' => '50',
    ]))->toBe(Command::SUCCESS);

    $secondRecords = exportDatasetRecords('anino-training/second/atake.jsonl');
    $firstSplits = collect($firstRecords)->pluck('split', 'context_hash')->all();
    $secondSplits = collect($secondRecords)->pluck('split', 'context_hash')->all();

    expect($secondSplits)->toBe($firstSplits);
});

test('manifest reports classes outcomes and exact file hashes', function () {
    Storage::fake('local');

    $user = User::factory()->create();
    $scan = Scan::factory()->complete()->create();
    $finding = exportDatasetFinding($scan, hash('sha256', 'manifest-context'));
    $assessment = exportDatasetAssessment($finding, 'atake', 'confirmed_tp');

    AiAssessmentFeedback::create([
        'assessment_id' => $assessment->id,
        'user_id' => $user->id,
        'verdict' => 'correct',
        'reviewed_at' => now(),
    ]);

    expect(Artisan::call('sast:export-ai-feedback', [
        '--output' => 'anino-training/manifest-test',
        '--validation-percent' => '0',
    ]))->toBe(Command::SUCCESS);

    $disk = Storage::disk('local');
    $manifest = json_decode(
        $disk->get('anino-training/manifest-test/manifest.json'),
        true,
        flags: JSON_THROW_ON_ERROR,
    );

    foreach (['atake.jsonl', 'depensa.jsonl'] as $filename) {
        $payload = $disk->get('anino-training/manifest-test/'.$filename);

        expect($manifest['files'][$filename]['sha256'])->toBe(hash('sha256', $payload))
            ->and($manifest['files'][$filename]['bytes'])->toBe(strlen($payload));
    }

    expect($manifest['record_count'])->toBe(1)
        ->and($manifest['counts']['reviewers'])->toBe(['atake' => 1, 'depensa' => 0])
        ->and($manifest['counts']['splits'])->toBe(['train' => 1, 'validation' => 0])
        ->and($manifest['classes']['confirmed_tp'])->toBe(1)
        ->and($manifest['outcomes']['true_positive'])->toBe(1);
});

test('export command rejects unsafe output paths and invalid validation percentages', function () {
    Storage::fake('local');

    expect(Artisan::call('sast:export-ai-feedback', [
        '--output' => '../outside',
    ]))->toBe(Command::FAILURE);

    expect(Artisan::call('sast:export-ai-feedback', [
        '--validation-percent' => '51',
    ]))->toBe(Command::FAILURE);

    expect(Storage::disk('local')->allFiles())->toBeEmpty();
});
