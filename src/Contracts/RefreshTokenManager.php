<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use SensitiveParameter;

interface RefreshTokenManager
{
    /** Issue a new opaque token (plaintext returned once) for any Authenticatable model. */
    public function issue(Authenticatable&Model $owner, IssueContext $context): NewRefreshToken;

    /**
     * Atomically redeem (rotate) a token. Null = unknown/expired/revoked/race-lost.
     * With `$ownerType` (a morph class), a token of another owner type is unknown
     * and is not consumed.
     */
    public function redeem(#[SensitiveParameter] string $plain, ?string $ownerType = null): ?RedemptionResult;

    /** Redeem then issue a same-family replacement in one call. Null on a failed redeem or a family killed by reuse mid-rotation. */
    public function rotate(#[SensitiveParameter] string $plain, ?RotationContext $context = null): ?RotationResult;

    /** Revoke by plaintext (logout with the token in hand); idempotent. */
    public function revoke(#[SensitiveParameter] string $plain, RevocationReason $reason = RevocationReason::Logout): void;

    /** Revoke every active token for an owner; returns the count revoked. */
    public function revokeAllFor(Authenticatable&Model $owner, RevocationReason $reason = RevocationReason::LogoutAll): int;
}
