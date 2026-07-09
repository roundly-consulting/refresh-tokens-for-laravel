<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Events;

/**
 * Fired once when an active session (refresh-token row) is revoked. Carries the
 * row id and the opaque access reference (if any) the host should deny.
 */
final class SessionRevoked
{
    public function __construct(
        public int|string $tokenId,
        public ?string $accessReference = null,
    ) {}
}
