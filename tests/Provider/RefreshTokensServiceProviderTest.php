<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\RefreshTokens\Commands\PruneRefreshTokensCommand;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\RefreshTokensManager;
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

it('binds the manager as a singleton and the default revoker', function (): void {
    expect(app(RefreshTokensManager::class))->toBe(app(RefreshTokensManager::class))
        ->and(app(AccessTokenRevoker::class))->toBeInstanceOf(NullAccessTokenRevoker::class);
});

it('registers the toolkit blueprint macros before the migrator runs', function (): void {
    expect(Blueprint::hasMacro('morphKey'))->toBeTrue();
});

it('reports the package in about', function (): void {
    Artisan::call('about', ['--only' => 'refresh-tokens']);
    $output = Artisan::output();

    expect($output)->toContain('Token model')
        ->and($output)->toContain('RefreshToken')
        ->and($output)->toContain('Owner')
        ->and($output)->toContain('morph (bigint)')
        ->and($output)->toContain('sha256')
        ->and($output)->toContain('NONE (no-op)');
});

/**
 * A — the secret-safe `about` capture.
 *
 * Purchases #13 is the bug this expectation exists for: the fleet's most credential-heavy
 * `about` section was guarded by negative assertions against `app(Kernel::class)->output()`,
 * which returns `''` — every "does not leak" check was vacuous. This package's own test was
 * already on the right reader and already guarded the guard, so adopting the expectation is
 * not a bug fix here; it is the same proof with the ordering enforced by the assertion
 * rather than by this file remembering to do it: (1) output non-empty, (2) every
 * `mustRender` string present, (3) only then no secret renders.
 *
 * It matters most here of anywhere: `hash.key` is the HMAC pepper standing between a leaked
 * database dump and every live token.
 */
it('never renders the pepper, the table name or a swapped model namespace in about', function (): void {
    config()->set('refresh-tokens.hash.key', 'super-secret-pepper-value');
    config()->set('refresh-tokens.table', 'acme_internal_refresh_tokens');
    config()->set('refresh-tokens.model', CustomRefreshToken::class);

    expect('refresh-tokens')->toLeakNoSecrets(
        secrets: [
            // The pepper participates in the at-rest digest of every token. It renders as
            // SET/MISSING and never as a value.
            'super-secret-pepper-value',
            // The host's table name is its topology, not the console's business.
            'acme_internal_refresh_tokens',
            // The model renders by base name, never its namespace — a namespace names the
            // host's own application structure.
            'RoundlyConsulting\RefreshTokens\Tests\Fixtures',
        ],
        mustRender: [
            // The positive half: each is the safe report standing in for one of the secrets
            // above, so it also proves the line rendered rather than being silently absent.
            'CustomRefreshToken',
            'SET',
            'CUSTOM',
        ],
    );
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

it('reports a blank algo as the sha256 default in about (strict config)', function (string $blank): void {
    config()->set('refresh-tokens.hash.algo', $blank);

    Artisan::call('about', ['--only' => 'refresh-tokens']);

    expect(Artisan::output())->toContain('sha256')
        ->not->toContain('INVALID');
})->with(['empty' => [''], 'whitespace' => ['  ']]);

it('reports the prune window in about', function (mixed $configured, string $expected): void {
    config()->set('refresh-tokens.prune.after', $configured);

    Artisan::call('about', ['--only' => 'refresh-tokens']);

    expect(Artisan::output())->toMatch('/Prune after\W+'.preg_quote($expected, '/').'/');
})->with([
    'below the floor' => [0, 'INVALID'],
    'junk' => ['soon', 'INVALID'],
    'numeric string' => ['7', '7 day(s)'],
]);

it('reports junk integers as INVALID in about rather than throwing (strict config)', function (string $key, string $row): void {
    config()->set($key, 'five');

    Artisan::call('about', ['--only' => 'refresh-tokens']);

    expect(Artisan::output())->toMatch('/'.preg_quote($row, '/').'\W+INVALID/');
})->with([
    'ttl' => ['refresh-tokens.ttl', 'Sliding TTL'],
    'absolute ttl' => ['refresh-tokens.absolute_ttl', 'Absolute TTL'],
    'token length' => ['refresh-tokens.token_length', 'Token length'],
    'grace' => ['refresh-tokens.rotation.grace', 'Rotation grace'],
]);

it('reads a numeric-string rotation grace in about', function (): void {
    config()->set('refresh-tokens.rotation.grace', '45');

    Artisan::call('about', ['--only' => 'refresh-tokens']);

    expect(Artisan::output())->toMatch('/Rotation grace\W+45s/');
});
