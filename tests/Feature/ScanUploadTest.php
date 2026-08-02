<?php

use App\Models\Project;
use App\Models\User;
use Inertia\Testing\AssertableInertia as Assert;

beforeEach(function () {
    $this->user = User::factory()->create();
    $this->project = Project::factory()->create();
});

test('authenticated users can view the scan upload page', function () {
    $this->actingAs($this->user);

    $this->get(route('scans.create'))
        ->assertOk()
        ->assertInertia(fn (Assert $page) => $page
            ->component('Scans/Upload')
            ->where('projects', fn ($projects) => count($projects) === 1 && $projects[0]['id'] === $this->project->id)
        );
});

test('guests are redirected from the scan upload page', function () {
    $response = $this->get(route('scans.create'));

    $response->assertRedirect(route('login'));
});
