<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Carbon\CarbonImmutable;

/**
 * The retention window every prune path shares — `RefreshTokens::prune()`, the
 * `refresh-tokens:prune` command and `php artisan model:prune` (through the model's
 * `prunable()`), so none of them can delete what another would keep.
 *
 * The window never drops below {@see self::MINIMUM_DAYS}. Pruning a token revoked
 * minutes ago would destroy reuse-detection evidence (re-presented, it finds no row and
 * fires no family revoke), and a negative window would put the cutoff in the future and
 * delete live tokens.
 *
 * @internal the package's own prune wiring — hosts configure `refresh-tokens.prune.after`.
 */
final class PruneWindow
{
    public const int MINIMUM_DAYS = 1;

    public const int DEFAULT_DAYS = 30;

    /**
     * The configured `refresh-tokens.prune.after`, clamped to the floor. An integer or a
     * numeric string (an env value) is read as days; anything else falls back to the
     * default.
     */
    public static function configuredDays(): int
    {
        $configured = config('refresh-tokens.prune.after', self::DEFAULT_DAYS);

        if (is_string($configured) && preg_match('/^\s*-?\d+\s*$/', $configured) === 1) {
            $configured = (int) $configured;
        }

        return max(self::MINIMUM_DAYS, is_int($configured) ? $configured : self::DEFAULT_DAYS);
    }

    /**
     * Rows revoked or expired before this instant are prunable.
     */
    public static function cutoff(?int $days = null): CarbonImmutable
    {
        return CarbonImmutable::now()->subDays($days ?? self::configuredDays());
    }
}
