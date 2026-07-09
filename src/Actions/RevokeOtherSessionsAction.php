<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Revoke every active session for a user except the one holding the current access
 * reference. Passing a null current reference revokes them all. Returns the count.
 */
final class RevokeOtherSessionsAction
{
    public function __construct(
        private readonly RevokeSessionAction $revokeSession,
    ) {}

    public function execute(
        Authenticatable $user,
        ?string $currentAccessReference,
        RevocationReason $reason = RevocationReason::LogoutAll,
    ): int {
        /** @var Collection<int, RefreshToken> $sessions */
        $sessions = TokenModel::query()
            ->where(TokenModel::foreignKey(), $user->getAuthIdentifier())
            ->active()
            ->get();

        $revoked = 0;

        foreach ($sessions as $session) {
            if ($currentAccessReference !== null && $session->access_reference === $currentAccessReference) {
                continue;
            }

            if ($this->revokeSession->execute($session, $reason)) {
                $revoked++;
            }
        }

        return $revoked;
    }
}
