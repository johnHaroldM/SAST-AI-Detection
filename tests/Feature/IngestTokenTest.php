<?php

use App\Models\Finding;
use App\Models\Project;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

beforeEach(function () {
    Storage::fake('local');
    Queue::fake();
    $this->user = User::factory()->create();
});

function sarifPayload(): string
{
    return json_encode(['version' => '2.1.0', 'runs' => [[
        'tool' => ['driver' => ['rules' => [['id' => 'php.demo', 'properties' => ['tags' => ['CWE-89']]]]]],
        'results' => [[
            'ruleId' => 'php.demo',
            'level' => 'error',
            'message' => ['text' => 'Demo finding'],
            'locations' => [['physicalLocation' => [
                'artifactLocation' => ['uri' => 'app/A.php'],
                'region' => ['startLine' => 4],
            ]]],
        ]],
    ]]]);
}

it('stores only a hash of the token', function () {
    $project = Project::factory()->create();
    $token = $project->issueIngestToken();

    $project->refresh();

    // A database dump must not hand over working upload credentials.
    expect($project->ingest_token_hash)->toBe(hash('sha256', $token))
        ->and($project->ingest_token_hash)->not->toBe($token)
        ->and($project->getAttributes())->not->toHaveKey('ingest_token');
});

it('never exposes the hash when the project is serialised', function () {
    $project = Project::factory()->create();
    $project->issueIngestToken();

    expect($project->fresh()->toArray())->not->toHaveKey('ingest_token_hash');
});

it('accepts an upload authenticated by the project token', function () {
    $project = Project::factory()->create();
    $token = $project->issueIngestToken();

    $this->withToken($token)
        ->post(route('ingest.scans.store'), [
            'source' => 'sarif',
            'commit_sha' => str_repeat('a', 40),
            'branch' => 'main',
            'report' => UploadedFile::fake()->createWithContent('r.sarif.json', sarifPayload()),
        ])
        ->assertStatus(202)
        ->assertJsonPath('project', $project->name);

    expect(Scan::where('project_id', $project->id)->exists())->toBeTrue();
});

it('binds the upload to the token\'s own project', function () {
    // A token must not be able to write scans against a different project,
    // even if one is named in the request.
    $mine = Project::factory()->create(['name' => 'Mine']);
    $other = Project::factory()->create(['name' => 'Other']);
    $token = $mine->issueIngestToken();

    $this->withToken($token)
        ->post(route('ingest.scans.store'), [
            'project_id' => $other->id,
            'source' => 'sarif',
            'commit_sha' => str_repeat('b', 40),
            'branch' => 'main',
            'report' => UploadedFile::fake()->createWithContent('r.json', sarifPayload()),
        ])
        ->assertStatus(202);

    expect(Scan::where('project_id', $mine->id)->count())->toBe(1)
        ->and(Scan::where('project_id', $other->id)->count())->toBe(0);
});

it('rejects a missing, wrong, or revoked token', function () {
    $project = Project::factory()->create();
    $token = $project->issueIngestToken();

    $payload = fn () => [
        'source' => 'sarif',
        'commit_sha' => str_repeat('c', 40),
        'branch' => 'main',
        'report' => UploadedFile::fake()->createWithContent('r.json', sarifPayload()),
    ];

    $this->post(route('ingest.scans.store'), $payload())->assertStatus(401);
    $this->withToken('sast_not-a-real-token')->post(route('ingest.scans.store'), $payload())->assertStatus(401);

    $project->revokeIngestToken();
    $this->withToken($token)->post(route('ingest.scans.store'), $payload())->assertStatus(401);

    expect(Scan::count())->toBe(0);
});

it('stops accepting a token once it expires', function () {
    // Revocation depends on somebody remembering. Expiry makes forgetting
    // the safe outcome, which is what protects a token pasted into a CI
    // config years ago and never thought about again.
    config()->set('sast.ingest.token_lifetime_days', 30);

    $project = Project::factory()->create();
    $token = $project->issueIngestToken();

    expect(Project::findByIngestToken($token)?->id)->toBe($project->id);

    $this->travel(31)->days();

    expect(Project::findByIngestToken($token))->toBeNull()
        ->and($project->fresh()->ingestTokenHasExpired())->toBeTrue();

    $this->withToken($token)->postJson(route('ingest.scans.store'), [
        'source' => 'sarif',
        'commit_sha' => str_repeat('e', 40),
        'branch' => 'main',
    ])->assertStatus(401);
});

it('honours a non-expiring token when explicitly requested', function () {
    config()->set('sast.ingest.token_lifetime_days', 0);

    $project = Project::factory()->create();
    $token = $project->issueIngestToken();

    expect($project->fresh()->ingest_token_expires_at)->toBeNull();

    $this->travel(5)->years();

    expect(Project::findByIngestToken($token)?->id)->toBe($project->id);
});

it('cannot tell an expired token apart from a wrong one', function () {
    // Identical 401s mean a probe learns nothing about whether a credential
    // ever existed for this installation.
    config()->set('sast.ingest.token_lifetime_days', 1);

    $project = Project::factory()->create();
    $expired = $project->issueIngestToken();
    $this->travel(2)->days();

    $payload = [
        'source' => 'sarif',
        'commit_sha' => str_repeat('f', 40),
        'branch' => 'main',
        'report' => UploadedFile::fake()->createWithContent('r.json', sarifPayload()),
    ];

    $expiredResponse = $this->withToken($expired)->post(route('ingest.scans.store'), $payload);
    $bogusResponse = $this->withToken('sast_completely-made-up')->post(route('ingest.scans.store'), $payload);

    expect($expiredResponse->status())->toBe($bogusResponse->status())
        ->and($expiredResponse->json('message'))->toBe($bogusResponse->json('message'));
});

it('invalidates the previous token when a new one is issued', function () {
    $project = Project::factory()->create();
    $first = $project->issueIngestToken();
    $second = $project->issueIngestToken();

    expect(Project::findByIngestToken($first))->toBeNull()
        ->and(Project::findByIngestToken($second)?->id)->toBe($project->id);
});

it('records when a token was last used', function () {
    $project = Project::factory()->create();
    $token = $project->issueIngestToken();

    expect($project->fresh()->ingest_token_last_used_at)->toBeNull();

    $this->withToken($token)->post(route('ingest.scans.store'), [
        'source' => 'sarif',
        'commit_sha' => str_repeat('d', 40),
        'branch' => 'main',
        'report' => UploadedFile::fake()->createWithContent('r.json', sarifPayload()),
    ])->assertStatus(202);

    expect($project->fresh()->ingest_token_last_used_at)->not->toBeNull();
});

it('grants no read access whatsoever', function () {
    // The token is write-only by construction: there is no read route on the
    // stateless ingest surface, and the session-authenticated API rejects it.
    $project = Project::factory()->create();
    $token = $project->issueIngestToken();
    $scan = Scan::factory()->for($project)->create();

    $this->withToken($token)->getJson(route('api.scans.show', $scan))->assertUnauthorized();
    $this->withToken($token)->getJson(route('api.rules.noisy'))->assertUnauthorized();
});

it('rejects a malformed report or commit sha', function () {
    $project = Project::factory()->create();
    $token = $project->issueIngestToken();

    $this->withToken($token)->postJson(route('ingest.scans.store'), [
        'source' => 'sarif',
        'commit_sha' => 'nope',
        'branch' => 'main',
    ])->assertStatus(422);
});

it('issues and revokes tokens from the dashboard', function () {
    $project = Project::factory()->create();

    $this->actingAs($this->user)
        ->post(route('projects.token.issue', $project))
        ->assertRedirect(route('projects.index'))
        // The plaintext is flashed exactly once and never persisted.
        ->assertSessionHas('ingestToken');

    expect($project->fresh()->hasIngestToken())->toBeTrue();

    $this->actingAs($this->user)
        ->delete(route('projects.token.revoke', $project))
        ->assertRedirect(route('projects.index'));

    expect($project->fresh()->hasIngestToken())->toBeFalse();
});

it('requires authentication to manage tokens', function () {
    $project = Project::factory()->create();

    $this->post(route('projects.token.issue', $project))->assertRedirect(route('login'));
    $this->delete(route('projects.token.revoke', $project))->assertRedirect(route('login'));
});

it('does not upload anything on a dry run', function () {
    $root = storage_path('app/testing/push-'.Str::random(6));
    mkdir($root.'/app', 0755, true);
    file_put_contents($root.'/app/V.php', '<?php class V { function r($x) { return unserialize($x); } }');

    $this->artisan('sast:push', ['path' => $root, '--dry-run' => true])->assertExitCode(0);

    expect(Scan::count())->toBe(0)
        ->and(Finding::count())->toBe(0);

    File::deleteDirectory($root);
});

it('refuses to upload without an endpoint and token', function () {
    $root = storage_path('app/testing/push-'.Str::random(6));
    mkdir($root, 0755, true);

    $this->artisan('sast:push', ['path' => $root, '--yes' => true])->assertExitCode(1);

    File::deleteDirectory($root);
});
