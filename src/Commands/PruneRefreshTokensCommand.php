<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\RefreshTokens\Actions\PruneRefreshTokensAction;
use RoundlyConsulting\RefreshTokens\RefreshTokensManager;

/**
 * Force-delete refresh tokens revoked or expired longer ago than the retention
 * window. The host schedules this (or `php artisan model:prune`); the package
 * does not self-schedule. A thin shell over `RefreshTokens::prune()`.
 */
final class PruneRefreshTokensCommand extends Command
{
    protected $signature = 'refresh-tokens:prune {--days= : Days past revoke/expiry to retain (min 1; defaults to config)}';

    protected $description = 'Force-delete refresh tokens revoked or expired past the retention window';

    public function handle(RefreshTokensManager $refreshTokens): int
    {
        $option = $this->option('days');
        $days = null;

        if (is_string($option) && $option !== '') {
            if (! ctype_digit($option) || (int) $option < PruneRefreshTokensAction::MINIMUM_DAYS) {
                $this->error('The --days option must be an integer of at least '.PruneRefreshTokensAction::MINIMUM_DAYS.' to preserve reuse-detection evidence.');

                return self::FAILURE;
            }

            $days = (int) $option;
        }

        $deleted = $refreshTokens->prune($days);

        $this->info("Pruned {$deleted} refresh token(s).");

        return self::SUCCESS;
    }
}
