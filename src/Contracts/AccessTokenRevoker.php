<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Contracts;

use RoundlyConsulting\RefreshTokens\Support\NullAccessTokenRevoker;
use SensitiveParameter;

/**
 * Bridges refresh-token revocation to the host's access-token layer. When a
 * session or family is revoked, the package calls this with the row's opaque
 * `access_reference` so the host (e.g. jwt-for-laravel's jti denylist) can kill
 * the matching access token.
 *
 * The default binding ({@see NullAccessTokenRevoker})
 * is a no-op, so the package works standalone; the host rebinds a real adapter.
 */
interface AccessTokenRevoker
{
    public function revoke(#[SensitiveParameter] string $accessReference): void;
}
