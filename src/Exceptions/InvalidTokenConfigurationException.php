<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Exceptions;

/**
 * Thrown when a security-relevant config value is unsafe: an unsupported hashing
 * algorithm, a token length outside the bounds, or a per-issue lifetime override
 * out of range. Failing loudly stops a one-line typo from silently degrading the
 * token store.
 */
final class InvalidTokenConfigurationException extends RefreshTokenException
{
    /**
     * @param  list<string>  $allowed
     */
    public static function unsupportedAlgorithm(string $algo, array $allowed): self
    {
        return new self(sprintf(
            'Unsupported refresh-tokens hash algorithm [%s]. Allowed: %s.',
            $algo,
            implode(', ', $allowed),
        ));
    }

    public static function tokenLengthTooShort(int $length, int $minimum): self
    {
        return new self(sprintf(
            'refresh-tokens token_length [%d] is below the minimum of %d.',
            $length,
            $minimum,
        ));
    }

    public static function tokenLengthTooLong(int $length, int $maximum): self
    {
        return new self(sprintf(
            'refresh-tokens token_length [%d] is above the maximum of %d.',
            $length,
            $maximum,
        ));
    }

    public static function invalidTtl(int $ttl): self
    {
        return new self(sprintf(
            'refresh-tokens issue ttl [%d] must be at least 1 second.',
            $ttl,
        ));
    }

    public static function invalidAbsoluteTtl(int $ttl): self
    {
        return new self(sprintf(
            'refresh-tokens issue absoluteTtl [%d] must be 0 (uncapped) or more seconds.',
            $ttl,
        ));
    }
}
