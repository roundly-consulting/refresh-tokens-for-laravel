<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Events;

/**
 * Fired when a refresh token is issued. Carries only the row id (serializable);
 * hosts hook this to dispatch asynchronous device/geo enrichment.
 */
final class RefreshTokenIssued
{
    public function __construct(
        public int|string $tokenId,
    ) {}
}
