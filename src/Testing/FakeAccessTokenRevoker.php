<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Testing;

use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Exceptions\RevokerAssertionFailedException;
use SensitiveParameter;

/**
 * A first-class testing double for {@see AccessTokenRevoker}. Bind it in place of
 * the host's real revoker and assert exactly which access references the package
 * asked to deny — no hand-rolled spy required:
 *
 * ```php
 * $fake = new FakeAccessTokenRevoker();
 * $this->app->instance(AccessTokenRevoker::class, $fake);
 * // … exercise reuse / revocation …
 * $fake->assertRevoked($jti);
 * $fake->assertRevokedCount(2);
 * ```
 *
 * Assertions throw a package exception rather than a PHPUnit assertion so the fake
 * lives in runtime autoload and works under any test runner.
 */
final class FakeAccessTokenRevoker implements AccessTokenRevoker
{
    /** @var list<string> */
    public array $revoked = [];

    public function revoke(#[SensitiveParameter] string $accessReference): void
    {
        $this->revoked[] = $accessReference;
    }

    public function assertRevoked(string $accessReference): void
    {
        if (! in_array($accessReference, $this->revoked, true)) {
            throw new RevokerAssertionFailedException(
                "Expected access reference [{$accessReference}] to be revoked, but it was not.",
            );
        }
    }

    public function assertNotRevoked(string $accessReference): void
    {
        if (in_array($accessReference, $this->revoked, true)) {
            throw new RevokerAssertionFailedException(
                "Expected access reference [{$accessReference}] not to be revoked, but it was.",
            );
        }
    }

    public function assertNothingRevoked(): void
    {
        if ($this->revoked !== []) {
            $count = count($this->revoked);

            throw new RevokerAssertionFailedException(
                "Expected no access references to be revoked, but {$count} were.",
            );
        }
    }

    public function assertRevokedCount(int $count): void
    {
        $actual = count($this->revoked);

        if ($actual !== $count) {
            throw new RevokerAssertionFailedException(
                "Expected {$count} access reference(s) to be revoked, but {$actual} were.",
            );
        }
    }
}
