<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens;

use Illuminate\Contracts\Foundation\Application;
use RoundlyConsulting\PackageToolkit\Concerns\RegistersBlueprintMacros;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\RefreshTokens\Commands\PruneRefreshTokensCommand;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\Contracts\SessionManager;
use RoundlyConsulting\RefreshTokens\Support\NullAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

final class RefreshTokensServiceProvider extends PackageServiceProvider
{
    use RegistersBlueprintMacros;

    public function configurePackage(Package $package): void
    {
        $package
            ->name('refresh-tokens')
            ->hasConfigFile()
            ->hasMigrations()
            ->hasCommands([PruneRefreshTokensCommand::class])
            ->contributesToAbout(fn (): array => $this->aboutSection());
    }

    public function register(): void
    {
        parent::register();

        // Registered here, not in boot(), so the `morphKey()` schema macro the
        // migration calls exists before the migrator can run.
        $this->registerBlueprintMacros();

        $this->app->singleton(RefreshTokens::class, fn (Application $app): RefreshTokens => new RefreshTokens($app));
        $this->app->alias(RefreshTokens::class, RefreshTokenManager::class);
        $this->app->alias(RefreshTokens::class, SessionManager::class);

        // Default no-op access-token revoker so the package works standalone; a host
        // (e.g. jwt-for-laravel's jti denylist) rebinds this to a real adapter.
        $this->app->singleton(AccessTokenRevoker::class, NullAccessTokenRevoker::class);
    }

    /**
     * The `about` payload.
     *
     * Secret-safe, and this package holds the most dangerous config value in the
     * fleet: `hash.key` is the HMAC pepper standing between a leaked database dump
     * and every live token. It renders as `SET`/`MISSING`, never as a value — and
     * neither a token hash nor a plaintext is reachable from config at all. The
     * host's table name renders as `DEFAULT`/`CUSTOM` and the bound revoker as
     * `BOUND`, so no host topology leaks either. Everything else is a constant: an
     * algorithm name, a TTL, a column name.
     *
     * @return array<string, string>
     */
    private function aboutSection(): array
    {
        $absolute = $this->seconds('refresh-tokens.absolute_ttl', 7_776_000);
        $grace = $this->seconds('refresh-tokens.rotation.grace', 0);
        $revoker = $this->app->make(AccessTokenRevoker::class);

        return [
            'Token model' => class_basename(TokenModel::class()),
            'Table' => TokenModel::table() === 'refresh_tokens' ? 'DEFAULT' : 'CUSTOM',
            'Owner' => 'morph ('.TokenModel::keyType()->value.')',
            'Sliding TTL' => $this->seconds('refresh-tokens.ttl', 2_592_000).'s',
            'Absolute TTL' => $absolute === 0 ? 'DISABLED' : $absolute.'s',
            'Token length' => $this->seconds('refresh-tokens.token_length', 64).' chars',
            'Hash algorithm' => $this->algorithm(),
            'Hash pepper' => $this->hasPepper() ? 'SET' : 'MISSING',
            'Rotation grace' => $grace === 0 ? 'STRICT' : $grace.'s',
            'Prune after' => $this->seconds('refresh-tokens.prune.after', 30).' day(s)',
            'Access-token revoker' => $revoker instanceof NullAccessTokenRevoker ? 'NONE (no-op)' : 'BOUND',
        ];
    }

    private function seconds(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_int($value) ? $value : $default;
    }

    /**
     * The at-rest digest name — a constant, never a secret. An algorithm outside
     * the allowlist renders as `INVALID` rather than throwing: `about` must report
     * a misconfiguration, not blow up on it.
     */
    private function algorithm(): string
    {
        $algo = config('refresh-tokens.hash.algo', 'sha256');

        return is_string($algo) && in_array($algo, TokenHasher::allowedAlgorithms(), true)
            ? $algo
            : 'INVALID';
    }

    private function hasPepper(): bool
    {
        $key = config('refresh-tokens.hash.key');

        return is_string($key) && trim($key) !== '';
    }
}
