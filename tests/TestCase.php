<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Tests;

use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Crypto\CryptoServiceProvider;
use RoundlyConsulting\RefreshTokens\RefreshTokensServiceProvider;
use RoundlyConsulting\Testing\PackageTestCase;

abstract class TestCase extends PackageTestCase
{
    /**
     * Every provider refresh-tokens hard-requires, in registration order. A host
     * auto-discovers these; the suite must list them or the test environment is a
     * fiction. Crypto is not optional — it owns the CSPRNG the token secret is drawn
     * from and the digest it is stored under.
     *
     * @return list<class-string<ServiceProvider>>
     */
    protected function packageProviders(): array
    {
        return [
            CryptoServiceProvider::class,
            RefreshTokensServiceProvider::class,
        ];
    }

    /**
     * The token table, named by provider class (never by filename), plus the host-owned
     * `users` fixture the tokens hang off.
     *
     * @return list<class-string<ServiceProvider>|string>
     */
    protected function migrationSources(): array
    {
        return [
            __DIR__.'/database/migrations',
            RefreshTokensServiceProvider::class,
        ];
    }

    /**
     * Applied BEFORE the providers boot — the only correct place, and load-bearing here:
     * the migration reads `refresh-tokens.user_model` (through `TokenModel::foreignKey()`
     * and `::keyType()`) to shape the foreign-key column, so setting it in a test body
     * would be read only after the table already existed.
     *
     * @return array<string, mixed>
     */
    protected function configBeforeBoot(): array
    {
        return ['refresh-tokens.user_model' => Fixtures\User::class];
    }
}
