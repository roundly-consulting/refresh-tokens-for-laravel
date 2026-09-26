<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Exceptions;

/**
 * Thrown when an issue is asked to inherit a `familyId` that does not exist for
 * the given owner, or that belongs to a family already killed by reuse detection
 * — preventing a graft into another owner's (or a dead) lineage — or to root a
 * `newFamilyId` that is malformed, already taken, or passed alongside `familyId`.
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

    public static function malformed(string $familyId): self
    {
        return new self(sprintf(
            'Refresh-token family id [%s] is not a valid UUID.',
            $familyId,
        ));
    }

    public static function alreadyExists(string $familyId): self
    {
        return new self(sprintf(
            'Refresh-token family [%s] already exists and cannot be rooted again.',
            $familyId,
        ));
    }

    public static function ambiguous(): self
    {
        return new self('An issue may inherit a familyId or root a newFamilyId, not both.');
    }
}
