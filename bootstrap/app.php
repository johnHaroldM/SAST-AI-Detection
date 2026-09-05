<?php

use App\Http\Middleware\HandleAppearance;
use App\Http\Middleware\HandleInertiaRequests;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Middleware\AddLinkHeadersForPreloadedAssets;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        then: function (): void {
            // The SAST JSON endpoints are consumed by this app's own Inertia
            // SPA, so they are loaded under the `web` group: they authenticate
            // with the session and stay CSRF-protected. Registering them in the
            // stateless `api` group would mean either no auth at all or adding
            // token auth for a caller that doesn't need it.
            Route::middleware('web')
                ->prefix('api')
                ->group(base_path('routes/api.php'));

            // Machine-facing ingestion: stateless, token-authenticated, and
            // outside the web group so it carries no session or CSRF token.
            Route::middleware('throttle:ingest')
                ->prefix('api')
                ->group(base_path('routes/ingest.php'));
        },
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->encryptCookies(except: ['appearance', 'sidebar_state']);

        $middleware->web(append: [
            HandleAppearance::class,
            HandleInertiaRequests::class,
            AddLinkHeadersForPreloadedAssets::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
