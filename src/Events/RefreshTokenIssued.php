<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Events;

/**
 * Fired when a refresh token is issued. Carries ids/scalars only (serializable);
 * hosts hook this to dispatch asynchronous device/geo enrichment. `ownerType` is
 * the owner's morph class, so a listener can tell a user's session from a
 * client's even when their ids collide.
 */
final class RefreshTokenIssued
{
    public function __construct(
        public int|string $tokenId,
        public string $familyId,
        public string $ownerType,
        public int|string $ownerId,
    ) {}
}
