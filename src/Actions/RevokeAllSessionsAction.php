<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;

/**
 * Revoke every active session for an owner (global logout). Thin wrapper over
 * {@see RevokeOtherSessionsAction} with no session preserved.
 */
final class RevokeAllSessionsAction
{
    public function __construct(
        private readonly RevokeOtherSessionsAction $revokeOthers,
    ) {}

    public function execute(Authenticatable&Model $owner, RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return $this->revokeOthers->execute($owner, null, $reason);
    }
}
