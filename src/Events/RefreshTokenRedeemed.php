<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Events;

/**
 * Fired once when a refresh token is legitimately redeemed (rotated) — the winning
 * branch of the atomic claim. Carries ids/scalars only (never the model or
 * plaintext); hosts hook this to audit rotations and meter session churn.
 */
final class RefreshTokenRedeemed
{
    public function __construct(
        public int|string $tokenId,
        public string $familyId,
        public int|string $userId,
    ) {}
}
