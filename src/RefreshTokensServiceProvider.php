<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens;

use Illuminate\Contracts\Foundation\Application;
use RoundlyConsulting\PackageToolkit\Concerns\RegistersBlueprintMacros;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\RefreshTokens\Commands\PruneRefreshTokensCommand;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Support\NullAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Support\PruneWindow;
use RoundlyConsulting\RefreshTokens\Support\RotationGrace;
use RoundlyConsulting\RefreshTokens\Support\Settings;
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

        $this->app->singleton(RefreshTokensManager::class, fn (Application $app): RefreshTokensManager => new RefreshTokensManager($app));

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
        $revoker = $this->app->make(AccessTokenRevoker::class);

        return [
            'Token model' => class_basename(TokenModel::class()),
            'Table' => TokenModel::table() === 'refresh_tokens' ? 'DEFAULT' : 'CUSTOM',
            'Owner' => 'morph ('.TokenModel::keyType()->value.')',
            'Sliding TTL' => $this->valid(static fn (): string => Settings::ttl().'s'),
            'Absolute TTL' => $this->valid(static fn (): string => Settings::absoluteTtl() === 0 ? 'DISABLED' : Settings::absoluteTtl().'s'),
            'Token length' => $this->valid(static fn (): string => Settings::tokenLength().' chars'),
            'Hash algorithm' => $this->algorithm(),
            'Hash pepper' => $this->hasPepper() ? 'SET' : 'MISSING',
            'Rotation grace' => $this->valid(static fn (): string => RotationGrace::seconds() === 0 ? 'STRICT' : RotationGrace::seconds().'s'),
            'Prune after' => $this->valid(static fn (): string => PruneWindow::configuredDays().' day(s)'),
            'Access-token revoker' => $revoker instanceof NullAccessTokenRevoker ? 'NONE (no-op)' : 'BOUND',
        ];
    }

    /**
     * A setting rendered through its strict reader — or `INVALID` when that reader
     * throws: `about` reports a misconfiguration rather than blowing up on it (the
     * real read paths still throw).
     *
     * @param  callable(): string  $render
     */
    private function valid(callable $render): string
    {
        try {
            return $render();
        } catch (InvalidTokenConfigurationException) {
            return 'INVALID';
        }
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
