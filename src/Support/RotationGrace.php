<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Carbon\CarbonImmutable;

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
     * The configured window in seconds; `0` (strict) for a missing, non-numeric or
     * non-positive value. A numeric string (an env value) is read as seconds.
     */
    public static function seconds(): int
    {
        $grace = config('refresh-tokens.rotation.grace', 0);

        if (is_string($grace) && preg_match('/^\s*\d+\s*$/', $grace) === 1) {
            $grace = (int) $grace;
        }

        return is_int($grace) && $grace > 0 ? $grace : 0;
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
