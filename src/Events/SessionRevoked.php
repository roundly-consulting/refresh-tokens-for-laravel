<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Events;

use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;

/**
 * Fired once when an active session (refresh-token row) is revoked — or when a
 * session caught mid-rotation (its redeemed row, before the replacement exists) is
 * sealed by a family-level revoke. Carries the row id, its family (the stable
 * session id), the owner, why it was revoked, and the opaque access reference (if
 * any) the host should deny.
 */
final class SessionRevoked
{
    public function __construct(
        public int|string $tokenId,
        public string $familyId,
        public string $ownerType,
        public int|string $ownerId,
        public RevocationReason $reason,
        public ?string $accessReference = null,
    ) {}
}
