<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Support\PruneWindow;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Force-delete refresh tokens revoked or expired longer ago than the retention window:
 * `$days`, or `refresh-tokens.prune.after` when null. Returns the count deleted.
 *
 * The window never drops below one day. Pruning a token revoked minutes ago would
 * destroy reuse-detection evidence: re-presented, it finds no row and fires no family
 * revoke. An explicit `$days` below the floor throws; a configured one is clamped —
 * the same {@see PruneWindow} `php artisan model:prune` reads through the model.
 */
final readonly class PruneRefreshTokensAction
{
    public const int MINIMUM_DAYS = PruneWindow::MINIMUM_DAYS;

    /**
     * @throws InvalidTokenConfigurationException
     */
    public function execute(?int $days = null): int
    {
        if ($days !== null && $days < self::MINIMUM_DAYS) {
            throw InvalidTokenConfigurationException::invalidPruneWindow($days, self::MINIMUM_DAYS);
        }

        return (int) TokenModel::query()
            ->deadBefore(PruneWindow::cutoff($days))
            ->forceDelete();
    }
}
