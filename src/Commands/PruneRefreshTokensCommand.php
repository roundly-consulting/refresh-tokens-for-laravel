<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Commands;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Force-delete refresh tokens revoked or expired longer ago than the retention
 * window. The host schedules this (or `php artisan model:prune`); the package
 * does not self-schedule.
 */
final class PruneRefreshTokensCommand extends Command
{
    protected $signature = 'refresh-tokens:prune {--days= : Days past revoke/expiry to retain (defaults to config)}';

    protected $description = 'Force-delete refresh tokens revoked or expired past the retention window';

    public function handle(): int
    {
        $days = $this->resolveDays();
        $cutoff = CarbonImmutable::now()->subDays($days);

        $deleted = (int) TokenModel::query()
            ->where(function (Builder $query) use ($cutoff): void {
                $query
                    ->where('revoked_at', '<', $cutoff)
                    ->orWhere('expires_at', '<', $cutoff);
            })
            ->forceDelete();

        $this->info("Pruned {$deleted} refresh token(s) older than {$days} day(s).");

        return self::SUCCESS;
    }

    private function resolveDays(): int
    {
        $option = $this->option('days');

        if (is_string($option) && $option !== '' && ctype_digit($option)) {
            return (int) $option;
        }

        $configured = config('refresh-tokens.prune.after', 30);

        return is_int($configured) && $configured >= 0 ? $configured : 30;
    }
}
