<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Facades;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\RefreshTokensManager;
use RoundlyConsulting\RefreshTokens\Support\OwnerSessions;
use RoundlyConsulting\RefreshTokens\Support\PendingIssue;
use RoundlyConsulting\RefreshTokens\Support\SessionHandle;
use RoundlyConsulting\RefreshTokens\Testing\RefreshTokensFake;

/**
 * @method static PendingIssue for(Authenticatable&Model $owner)
 * @method static NewRefreshToken issue(Authenticatable&Model $owner, IssueContext $context)
 * @method static RedemptionResult|null redeem(string $plain, ?string $ownerType = null)
 * @method static RotationResult|null rotate(string $plain, ?RotationContext $context = null)
 * @method static bool revoke(string $plain, RevocationReason $reason = RevocationReason::Logout)
 * @method static OwnerSessions sessions(Authenticatable&Model $owner)
 * @method static SessionHandle session(RefreshToken|int|string $session)
 * @method static int prune(?int $days = null)
 *
 * @see RefreshTokensManager
 */
final class RefreshTokens extends Facade
{
    /**
     * Swap the manager for a recording fake. Calls still run for real — tokens are
     * issued, redeemed and revoked in the database — and every one is recorded for
     * the `assert*()` helpers, whether it came through the facade, an injected
     * manager, a sub-accessor or the `HasRefreshTokens` trait.
     */
    public static function fake(): RefreshTokensFake
    {
        $fake = new RefreshTokensFake(self::getFacadeApplication() ?? app());

        self::swap($fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return RefreshTokensManager::class;
    }
}
