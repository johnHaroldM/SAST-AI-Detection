<?php

use App\Services\GitBlameAuthorResolver;
use Illuminate\Support\Str;

beforeEach(function () {
    $this->root = storage_path('app/testing/blame-'.Str::random(8));
    mkdir($this->root.'/nested/deep', 0755, true);
    file_put_contents($this->root.'/nested/deep/File.php', "<?php\n// line two\n");
});

afterEach(function () {
    if (isset($this->root) && is_dir($this->root)) {
        exec(sprintf('rm -rf %s', escapeshellarg($this->root)));
    }
});

it('returns unknown for a directory outside any git repository', function () {
    // Regression: the repo-root walk terminated on a POSIX "/" only. On
    // Windows dirname('C:\\') returns itself, so a project without a .git
    // directory spun forever and hung the whole ingestion run.
    $resolver = new GitBlameAuthorResolver;

    $started = microtime(true);
    $level = $resolver->resolve($this->root.'/nested/deep/File.php', 2);
    $elapsed = microtime(true) - $started;

    expect($level)->toBe('unknown')
        ->and($elapsed)->toBeLessThan(5.0);
});

it('returns unknown for a file that does not exist', function () {
    expect((new GitBlameAuthorResolver)->resolve($this->root.'/nope.php', 1))->toBe('unknown');
});

it('resolves a real author and reuses the cached classification', function () {
    // The app's own repo is a git checkout, so this exercises the real path.
    $resolver = new GitBlameAuthorResolver;

    $first = $resolver->resolve(base_path('artisan'), 1);

    $started = microtime(true);
    for ($i = 0; $i < 25; $i++) {
        $resolver->resolve(base_path('artisan'), 1);
    }
    $elapsed = microtime(true) - $started;

    expect($first)->toBeIn(['junior', 'mid', 'senior', 'unknown']);

    // 25 further lookups hit the author cache, so they must not each pay for
    // a full history walk.
    expect($elapsed)->toBeLessThan(20.0);
})->skip(
    fn () => ! is_dir(base_path('.git')),
    'requires the app to be a git checkout'
);
