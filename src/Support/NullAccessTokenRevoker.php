<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use SensitiveParameter;

/**
 * Default no-op {@see AccessTokenRevoker} binding so the package works with zero
 * host wiring. A host that mints access tokens (e.g. jwt-for-laravel) rebinds this
 * to an adapter that denylists the matching access token.
 */
final class NullAccessTokenRevoker implements AccessTokenRevoker
{
    public function revoke(#[SensitiveParameter] string $accessReference): void
    {
        // Intentionally does nothing — access-token revocation is a host concern.
    }
}
