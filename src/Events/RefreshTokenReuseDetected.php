<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Events;

/**
 * Fired once when an already-rotated (or revoked) token is presented again — a
 * theft signal. The whole family is revoked; hosts hook this for alerting/audit.
 */
final class RefreshTokenReuseDetected
{
    public function __construct(
        public string $familyId,
        public int|string $userId,
    ) {}
}
