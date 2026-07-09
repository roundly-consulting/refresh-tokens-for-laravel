<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Events;

/**
 * Fired once when an already-rotated (or revoked) token is presented again — a
 * theft signal. The whole family is revoked; hosts hook this for alerting/audit.
 * `revokedCount` reports how many live family members were revoked in response, so
 * alerting can gauge the blast radius.
 */
final class RefreshTokenReuseDetected
{
    public function __construct(
        public string $familyId,
        public int|string $userId,
        public int $revokedCount = 0,
    ) {}
}
