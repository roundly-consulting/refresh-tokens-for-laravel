<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Exceptions;

/**
 * Thrown when an issue is asked to inherit a `familyId` that does not exist for
 * the given owner, or that belongs to a family already killed by reuse detection.
 * Prevents grafting a token into another user's — or a dead — lineage.
 */
final class InvalidTokenFamilyException extends RefreshTokenException
{
    public static function unknownForOwner(string $familyId): self
    {
        return new self(sprintf(
            'No live refresh-token family [%s] exists for the given owner.',
            $familyId,
        ));
    }

    public static function reuseRevoked(string $familyId): self
    {
        return new self(sprintf(
            'Refresh-token family [%s] was revoked by reuse detection and cannot be extended.',
            $familyId,
        ));
    }
}
