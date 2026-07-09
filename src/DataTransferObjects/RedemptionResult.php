<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

use Illuminate\Contracts\Auth\Authenticatable;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

/**
 * The successful outcome of redeeming (rotating) a token: the owning user, the
 * family lineage id the replacement should inherit, and the now-revoked row.
 */
final readonly class RedemptionResult
{
    public function __construct(
        public Authenticatable $user,
        public string $familyId,
        public RefreshToken $redeemedToken,
    ) {}
}
