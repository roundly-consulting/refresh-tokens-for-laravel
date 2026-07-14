<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\RefreshTokens\Commands\PruneRefreshTokensCommand;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\Contracts\SessionManager;
use RoundlyConsulting\RefreshTokens\RefreshTokens;
use RoundlyConsulting\RefreshTokens\RefreshTokensServiceProvider;
use RoundlyConsulting\RefreshTokens\Support\NullAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\CustomRefreshToken;

/** @return array<string, string> */
function publishesFor(string $tag): array
{
    return ServiceProvider::pathsToPublish(RefreshTokensServiceProvider::class, $tag);
}

it('never auto-loads its migrations', function (): void {
    // Fleet policy: a package publishes its migrations and loads nothing. A bare
    // `php artisan migrate` in a host must not create this package's table.
    expect(app('migrator')->paths())->not->toContain(realpath(__DIR__.'/../../database/migrations'));
});

it('publishes the migration under the unchanged tag, timestamp-injected', function (): void {
    $published = publishesFor('refresh-tokens-migrations');

    expect($published)->toHaveCount(1);

    $destination = basename((string) array_values($published)[0]);

    expect($destination)->toMatch('/^\d{4}_\d{2}_\d{2}_\d{6}_create_refresh_tokens_table\.php$/')
        ->and(array_keys($published)[0])->toEndWith('database/migrations/2026_07_08_000000_create_refresh_tokens_table.php');
});

it('publishes the config file under the unchanged tag', function (): void {
    $published = publishesFor('refresh-tokens-config');

    expect(array_values(array_map('basename', $published)))->toBe(['refresh-tokens.php'])
        ->and(array_keys($published)[0])->toEndWith('config/refresh-tokens.php');
});

it('registers the prune command', function (): void {
    expect(array_keys(Artisan::all()))->toContain('refresh-tokens:prune')
        ->and(app(PruneRefreshTokensCommand::class))->toBeInstanceOf(PruneRefreshTokensCommand::class);
});

it('binds the manager, both contracts and the default revoker', function (): void {
    expect(app(RefreshTokens::class))->toBe(app(RefreshTokens::class))
        ->and(app(RefreshTokenManager::class))->toBe(app(RefreshTokens::class))
        ->and(app(SessionManager::class))->toBe(app(RefreshTokens::class))
        ->and(app(AccessTokenRevoker::class))->toBeInstanceOf(NullAccessTokenRevoker::class);
});

it('registers the toolkit blueprint macros before the migrator runs', function (): void {
    expect(Blueprint::hasMacro('ownerKey'))->toBeTrue();
});

it('reports the package in about', function (): void {
    Artisan::call('about', ['--only' => 'refresh-tokens']);
    $output = Artisan::output();

    expect($output)->toContain('Token model')
        ->and($output)->toContain('RefreshToken')
        ->and($output)->toContain('Owner key')
        ->and($output)->toContain('user_id (bigint)')
        ->and($output)->toContain('sha256')
        ->and($output)->toContain('NONE (no-op)');
});

it('never renders the pepper, the table name or a swapped model namespace in about', function (): void {
    config()->set('refresh-tokens.hash.key', 'super-secret-pepper-value');
    config()->set('refresh-tokens.table', 'acme_internal_refresh_tokens');
    config()->set('refresh-tokens.model', CustomRefreshToken::class);

    Artisan::call('about', ['--only' => 'refresh-tokens']);
    $output = Artisan::output();

    // Guard the guard: an empty capture would make every negative below vacuous.
    expect($output)->toContain('CustomRefreshToken')
        ->and($output)->toContain('SET')
        ->and($output)->toContain('CUSTOM');

    expect($output)->not->toContain('super-secret-pepper-value')
        ->and($output)->not->toContain('acme_internal_refresh_tokens')
        // The model renders by base name, never its namespace.
        ->and($output)->not->toContain('RoundlyConsulting\RefreshTokens\Tests\Fixtures');
});

it('reports a missing pepper and a disabled absolute ttl', function (): void {
    config()->set('refresh-tokens.hash.key', '   ');
    config()->set('refresh-tokens.absolute_ttl', 0);
    config()->set('refresh-tokens.rotation.grace', 30);
    config()->set('refresh-tokens.hash.algo', 'md5');

    Artisan::call('about', ['--only' => 'refresh-tokens']);
    $output = Artisan::output();

    expect($output)->toContain('MISSING')
        ->and($output)->toContain('DISABLED')
        ->and($output)->toContain('30s')
        // An algo outside the allowlist is reported, not thrown on.
        ->and($output)->toContain('INVALID')
        ->and($output)->not->toContain('md5');
});
