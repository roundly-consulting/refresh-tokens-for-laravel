<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\RefreshTokens\Commands\PruneRefreshTokensCommand;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\Contracts\SessionManager;
use RoundlyConsulting\RefreshTokens\Support\NullAccessTokenRevoker;

final class RefreshTokensServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/refresh-tokens.php', 'refresh-tokens');

        $this->app->singleton(RefreshTokens::class, fn (Application $app): RefreshTokens => new RefreshTokens($app));
        $this->app->alias(RefreshTokens::class, RefreshTokenManager::class);
        $this->app->alias(RefreshTokens::class, SessionManager::class);

        // Default no-op access-token revoker so the package works standalone; a host
        // (e.g. jwt-for-laravel's jti denylist) rebinds this to a real adapter.
        $this->app->singleton(AccessTokenRevoker::class, NullAccessTokenRevoker::class);
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->commands([
                PruneRefreshTokensCommand::class,
            ]);

            $this->publishes([
                __DIR__.'/../config/refresh-tokens.php' => config_path('refresh-tokens.php'),
            ], 'refresh-tokens-config');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'refresh-tokens-migrations');
        }
    }
}
