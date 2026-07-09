<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use SensitiveParameter;

interface RefreshTokenManager
{
    /** Issue a new opaque token (plaintext returned once). */
    public function issue(Authenticatable $user, IssueContext $context): NewRefreshToken;

    /** Atomically redeem (rotate) a token. Null = unknown/expired/revoked/race-lost. */
    public function redeem(#[SensitiveParameter] string $plain): ?RedemptionResult;

    /** Redeem then issue a same-family replacement in one call. Null on a failed redeem. */
    public function rotate(#[SensitiveParameter] string $plain, ?string $linkedTo = null): ?RotationResult;

    /** Revoke by plaintext (logout with the token in hand); idempotent. */
    public function revoke(#[SensitiveParameter] string $plain): void;

    /** Revoke every active token for a user; returns the count revoked. */
    public function revokeAllFor(Authenticatable $user): int;
}
