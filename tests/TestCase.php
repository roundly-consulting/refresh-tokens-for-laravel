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
     * `users` and `clients` fixtures — two owner models whose ids collide on purpose.
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
}
