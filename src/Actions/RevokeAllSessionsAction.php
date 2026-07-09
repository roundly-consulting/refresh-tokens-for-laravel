<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;

/**
 * Revoke every active session for a user (global logout). Thin wrapper over
 * {@see RevokeOtherSessionsAction} with no session preserved.
 */
final class RevokeAllSessionsAction
{
    public function __construct(
        private readonly RevokeOtherSessionsAction $revokeOthers,
    ) {}

    public function execute(Authenticatable $user, RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return $this->revokeOthers->execute($user, null, $reason);
    }
}
