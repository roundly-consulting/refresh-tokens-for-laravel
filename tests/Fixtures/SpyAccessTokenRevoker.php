<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Tests\Fixtures;

use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use SensitiveParameter;

/**
 * Records every access reference it is asked to revoke so tests can assert the
 * host callback fired exactly the expected number of times.
 */
final class SpyAccessTokenRevoker implements AccessTokenRevoker
{
    /** @var list<string> */
    public array $revoked = [];

    public function revoke(#[SensitiveParameter] string $accessReference): void
    {
        $this->revoked[] = $accessReference;
    }
}
