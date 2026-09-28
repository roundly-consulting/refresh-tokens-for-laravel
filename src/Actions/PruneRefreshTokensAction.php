<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Force-delete refresh tokens revoked or expired longer ago than the retention window:
 * `$days`, or `refresh-tokens.prune.after` when null. Returns the count deleted.
 *
 * The window never drops below one day. Pruning a token revoked minutes ago would
 * destroy reuse-detection evidence: re-presented, it finds no row and fires no family
 * revoke. An explicit `$days` below the floor throws; a configured one is clamped.
 */
final readonly class PruneRefreshTokensAction
{
    public const int MINIMUM_DAYS = 1;

    /**
     * @throws InvalidTokenConfigurationException
     */
    public function execute(?int $days = null): int
    {
        if ($days !== null && $days < self::MINIMUM_DAYS) {
            throw InvalidTokenConfigurationException::invalidPruneWindow($days, self::MINIMUM_DAYS);
        }

        $cutoff = CarbonImmutable::now()->subDays($days ?? $this->configuredDays());

        return (int) TokenModel::query()
            ->where(function (Builder $query) use ($cutoff): void {
                $query
                    ->where('revoked_at', '<', $cutoff)
                    ->orWhere('expires_at', '<', $cutoff);
            })
            ->forceDelete();
    }

    private function configuredDays(): int
    {
        $configured = config('refresh-tokens.prune.after', 30);

        return max(self::MINIMUM_DAYS, is_int($configured) ? $configured : 30);
    }
}
