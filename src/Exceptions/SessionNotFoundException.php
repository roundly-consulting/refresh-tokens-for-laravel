<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Exceptions;

/**
 * Thrown when enriching a session whose id does not exist.
 */
final class SessionNotFoundException extends RefreshTokenException
{
    public static function forId(int|string $id): self
    {
        return new self("No refresh-token session found for id [{$id}].");
    }
}
