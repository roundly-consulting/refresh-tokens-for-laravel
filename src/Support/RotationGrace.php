<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Carbon\CarbonImmutable;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;

/**
 * The `refresh-tokens.rotation.grace` window: how long after a rotation a re-presented
 * token still counts as a benign single-flight retry rather than reuse. Shared by
 * redemption and by logout-with-token, so both read a spent token the same way.
 *
 * @internal the package's own reuse wiring — hosts configure `rotation.grace`.
 */
final class RotationGrace
{
    /**
     * The configured window in seconds; `0` (strict) when absent. An int or a canonical
     * integer string (an env value) of 0 or more — anything else throws rather than
     * silently reading as strict.
     *
     * @throws InvalidTokenConfigurationException
     */
    public static function seconds(): int
    {
        return Settings::integer('refresh-tokens.rotation.grace', config('refresh-tokens.rotation.grace'), 0, min: 0);
    }

    /**
     * Whether a token revoked at `$revokedAt` is still inside the window at `$now`.
     */
    public static function covers(CarbonImmutable $revokedAt, CarbonImmutable $now): bool
    {
        $grace = self::seconds();

        return $grace > 0 && $now->lessThanOrEqualTo($revokedAt->addSeconds($grace));
    }
}
