<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use SensitiveParameter;

/**
 * Atomically redeem (rotate) a refresh token — {@see AttemptRedemptionAction} with every
 * failure collapsed to `null`, so a caller cannot tell unknown from expired from revoked
 * from race-lost. Use `RefreshTokens::attempt()` to tell a token rotated moments ago
 * (its session alive) apart from the rest.
 *
 * Given an `$ownerType` (an owner morph class) the lookup is scoped to it: a token
 * belonging to another owner type is invisible — null, not claimed, no family
 * revoke, no event.
 */
final readonly class RedeemRefreshTokenAction
{
    public function __construct(
        private AttemptRedemptionAction $attempt,
    ) {}

    public function execute(#[SensitiveParameter] string $plain, ?string $ownerType = null): ?RedemptionResult
    {
        return $this->attempt->execute($plain, $ownerType)->result;
    }
}
