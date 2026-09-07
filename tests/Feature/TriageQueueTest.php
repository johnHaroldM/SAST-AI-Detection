<?php

use App\Models\Finding;
use App\Models\Project;
use App\Models\Rule;
use App\Models\Scan;
use App\Models\TriageFeedback;
use App\Models\User;
use App\Services\Triage\TriageGuidance;

beforeEach(function () {
    $this->user = User::factory()->create();
    config()->set('sast.training.min_training_samples', 50);
});

it('groups the queue by rule, biggest first', function () {
    Finding::factory()->count(7)->vectorized()->create(['rule_id' => 'php.security.path-traversal', 'cwe_id' => 22]);
    Finding::factory()->count(3)->vectorized()->create(['rule_id' => 'php.security.weak-hashing', 'cwe_id' => 327]);

    $this->actingAs($this->user)
        ->get(route('triage.queue'))
        ->assertOk()
        ->assertInertia(fn ($page) => $page
            ->component('Triage/Queue')
            ->where('breakdown.0.rule_id', 'php.security.path-traversal')
            ->where('breakdown.0.pending', 7)
            ->where('breakdown.1.pending', 3)
            // Highest-volume rule is focused by default, so the biggest win
            // is the first thing offered.
            ->where('focusedRule', 'php.security.path-traversal')
        );
});

it('only queues findings that still need a label', function () {
    Finding::factory()->count(4)->vectorized()->create(['rule_id' => 'r.one']);
    Finding::factory()->count(6)->labeled('true_positive')->create(['rule_id' => 'r.one']);

    $this->actingAs($this->user)
        ->get(route('triage.queue'))
        ->assertOk()
        ->assertInertia(fn ($page) => $page->where('findings.total', 4));
});

it('can focus a specific rule', function () {
    Finding::factory()->count(5)->vectorized()->create(['rule_id' => 'php.security.path-traversal']);
    Finding::factory()->count(2)->vectorized()->create(['rule_id' => 'php.security.weak-hashing']);

    $this->actingAs($this->user)
        ->get(route('triage.queue', ['rule' => 'php.security.weak-hashing']))
        ->assertOk()
        ->assertInertia(fn ($page) => $page
            ->where('focusedRule', 'php.security.weak-hashing')
            ->where('findings.total', 2)
        );
});

it('can filter the queue to a single project', function () {
    $mine = Project::factory()->create(['name' => 'Mine']);
    $other = Project::factory()->create(['name' => 'Other']);

    Finding::factory()->count(3)->vectorized()->create([
        'rule_id' => 'r.shared',
        'scan_id' => Scan::factory()->for($mine),
    ]);
    Finding::factory()->count(5)->vectorized()->create([
        'rule_id' => 'r.shared',
        'scan_id' => Scan::factory()->for($other),
    ]);

    $this->actingAs($this->user)
        ->get(route('triage.queue', ['project' => $mine->id]))
        ->assertOk()
        ->assertInertia(fn ($page) => $page->where('findings.total', 3));
});

it('ships judging guidance for the CWEs on the page', function () {
    Finding::factory()->count(2)->vectorized()->create(['rule_id' => 'r.sqli', 'cwe_id' => 89]);

    $this->actingAs($this->user)
        ->get(route('triage.queue'))
        ->assertOk()
        ->assertInertia(fn ($page) => $page
            ->where('guidance.89.title', 'SQL injection')
            ->has('guidance.89.truePositive')
            ->has('guidance.89.falsePositive')
        );
});

it('reports live progress toward the training threshold', function () {
    $truePositives = Finding::factory()->count(3)->labeled('true_positive')->create();
    $falsePositives = Finding::factory()->count(2)->labeled('false_positive')->create();

    foreach ($truePositives->concat($falsePositives) as $finding) {
        TriageFeedback::create([
            'finding_id' => $finding->id,
            'user_id' => $this->user->id,
            'corrected_label' => $finding->final_label,
            'source' => 'human',
        ]);
    }

    Finding::factory()->count(4)->vectorized()->create();

    $this->actingAs($this->user)
        ->get(route('triage.queue'))
        ->assertOk()
        ->assertInertia(fn ($page) => $page
            ->where('readiness.total', 5)
            ->where('readiness.true_positive', 3)
            ->where('readiness.false_positive', 2)
            ->where('readiness.ready', false)
        );
});

it('requires authentication', function () {
    $this->get(route('triage.queue'))->assertRedirect(route('login'));
});

it('retracts a label and restores the finding to the queue', function () {
    // Labelling at speed means occasional mistakes, and a wrong label teaches
    // the classifier the opposite of the truth.
    $finding = Finding::factory()->vectorized()->create();

    $this->actingAs($this->user)
        ->postJson(route('api.findings.triage', $finding), ['corrected_label' => 'true_positive'])
        ->assertOk();

    expect($finding->fresh()->final_label)->toBe('true_positive')
        ->and(TriageFeedback::count())->toBe(1);

    $this->actingAs($this->user)
        ->deleteJson(route('api.findings.untriage', $finding))
        ->assertOk()
        ->assertJsonPath('final_label', null);

    $finding->refresh();

    expect($finding->final_label)->toBeNull()
        ->and($finding->status)->toBe('pending')
        ->and(TriageFeedback::count())->toBe(0);
});

it('rolls the rule false-positive rate back when a label is retracted', function () {
    $rule = Rule::factory()->create(['external_id' => 'php.noisy']);
    $findings = Finding::factory()->count(2)->vectorized()->create(['rule_id' => 'php.noisy']);

    foreach ($findings as $finding) {
        $this->actingAs($this->user)->postJson(route('api.findings.triage', $finding), [
            'corrected_label' => 'false_positive',
        ])->assertOk();
    }

    expect($rule->fresh()->historical_fp_rate)->toBe(1.0)
        ->and($rule->fresh()->total_seen)->toBe(2);

    $this->actingAs($this->user)
        ->deleteJson(route('api.findings.untriage', $findings->first()))
        ->assertOk();

    expect($rule->fresh()->total_seen)->toBe(1);
});

it('requires authentication to retract a label', function () {
    $finding = Finding::factory()->labeled('true_positive')->create();

    $this->deleteJson(route('api.findings.untriage', $finding))->assertUnauthorized();

    expect($finding->fresh()->final_label)->toBe('true_positive');
});

it('offers concrete criteria for every rule the scanner emits', function () {
    $guidance = app(TriageGuidance::class);

    foreach ([89, 78, 502, 22, 79, 915, 327, 798] as $cwe) {
        $entry = $guidance->for($cwe);

        expect($entry['truePositive'])->not->toBe($guidance->for(null)['truePositive'])
            ->and($entry['title'])->not->toBe('Security finding');
    }

    // Unknown CWEs still get usable generic criteria rather than nothing.
    expect($guidance->for(9999)['title'])->toBe('Security finding');
});

it('pairs every CWE with impact, a fix, and a before/after example', function () {
    // A finding a reviewer cannot act on is only half useful — especially for
    // someone still learning what each vulnerability class means.
    $guidance = app(TriageGuidance::class);

    foreach ($guidance->knownCwes() as $cwe) {
        $advice = $guidance->for($cwe);

        expect($advice)->toHaveKeys(['risk', 'fix', 'vulnerable', 'secure', 'reference'])
            ->and($advice['risk'])->not->toBeEmpty()
            ->and($advice['fix'])->not->toBeEmpty()
            ->and($advice['vulnerable'])->not->toBeEmpty()
            ->and($advice['secure'])->not->toBe($advice['vulnerable'])
            ->and($advice['reference'])->toStartWith('https://');
    }
});

it('ships remediation alongside the findings on a scan page', function () {
    $scan = Scan::factory()->create();
    Finding::factory()->count(2)->vectorized()->create(['scan_id' => $scan->id, 'cwe_id' => 22]);

    $this->actingAs($this->user)
        ->get(route('scans.show', $scan))
        ->assertOk()
        ->assertInertia(fn ($page) => $page
            ->component('Scans/Show')
            ->where('guidance.22.title', 'Path traversal')
            ->has('guidance.22.risk')
            ->has('guidance.22.fix')
        );
});
