<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Exceptions;

/**
 * Thrown when a security-relevant config value is unsafe: an unsupported hashing
 * algorithm or a token length below the enforced minimum. Failing loudly stops a
 * one-line env typo from silently degrading the token store.
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

    public static function unsupportedUserKeyType(string $type): self
    {
        return new self(sprintf(
            'Unsupported refresh-tokens user_key_type [%s]. Allowed: id, uuid, ulid.',
            $type,
        ));
    }
}
