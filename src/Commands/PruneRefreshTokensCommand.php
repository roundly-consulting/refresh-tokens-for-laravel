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
    /**
     * The minimum retention floor. Pruning tokens revoked less than a day ago would
     * destroy reuse-detection evidence — a rotated token pruned minutes after
     * revocation, then re-presented, finds no row and fires no family revoke.
     */
    private const int MINIMUM_DAYS = 1;

    protected $signature = 'refresh-tokens:prune {--days= : Days past revoke/expiry to retain (min 1; defaults to config)}';

    protected $description = 'Force-delete refresh tokens revoked or expired past the retention window';

    public function handle(): int
    {
        $option = $this->option('days');

        if (is_string($option) && $option !== '' && (! ctype_digit($option) || (int) $option < self::MINIMUM_DAYS)) {
            $this->error('The --days option must be an integer of at least '.self::MINIMUM_DAYS.' to preserve reuse-detection evidence.');

            return self::FAILURE;
        }

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
            return max(self::MINIMUM_DAYS, (int) $option);
        }

        $configured = config('refresh-tokens.prune.after', 30);
        $configured = is_int($configured) ? $configured : 30;

        return max(self::MINIMUM_DAYS, $configured);
    }
}
