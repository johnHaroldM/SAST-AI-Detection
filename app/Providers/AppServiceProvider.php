<?php

namespace App\Providers;

use App\Services\Scanner\ProjectScanner;
use Carbon\CarbonImmutable;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Validation\Rules\Password;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // The scanner's rule set is config-driven so a deployment can disable
        // a rule that is unhelpfully noisy for its codebase without a code
        // change — and so tests can scan with a single rule in isolation.
        $this->app->singleton(ProjectScanner::class, function ($app): ProjectScanner {
            return new ProjectScanner(
                rules: array_map(
                    fn (string $rule) => $app->make($rule),
                    (array) config('sast.scanner.rules', []),
                ),
                // The scanner itself reads no configuration — this binding is
                // the only place the framework and the analyser meet, which
                // is what keeps the analyser distributable on its own.
                excludedDirectories: array_values((array) config('sast.scanner.exclude_directories', [])),
                maxFileBytes: (int) config('sast.scanner.max_file_bytes', 1_000_000),
            );
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->configureDefaults();
    }

    /**
     * Configure default behaviors for production-ready applications.
     */
    protected function configureDefaults(): void
    {
        Date::use(CarbonImmutable::class);

        // Ingestion is unauthenticated until the token is checked, so it is
        // rate limited by IP to blunt token guessing and upload floods.
        RateLimiter::for('ingest', fn (Request $request) => [
            Limit::perMinute(30)->by($request->ip()),
            Limit::perDay(500)->by($request->ip()),
        ]);

        DB::prohibitDestructiveCommands(
            app()->isProduction(),
        );

        Password::defaults(fn (): ?Password => app()->isProduction()
            ? Password::min(12)
                ->mixedCase()
                ->letters()
                ->numbers()
                ->symbols()
                ->uncompromised()
            : null,
        );
    }
}
