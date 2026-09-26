<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use SensitiveParameter;

/**
 * Revoke every active session for an owner except the one holding the current access
 * reference. Passing a null current reference revokes them all. Sessions caught
 * mid-rotation are sealed first ({@see SealPendingRotationsAction}). Returns the count.
 */
final class RevokeOtherSessionsAction
{
    public function __construct(
        private readonly RevokeSessionAction $revokeSession,
        private readonly SealPendingRotationsAction $seal,
    ) {}

    public function execute(
        Authenticatable&Model $owner,
        #[SensitiveParameter] ?string $currentAccessReference,
        RevocationReason $reason = RevocationReason::LogoutAll,
    ): int {
        $sealed = $this->seal->execute(
            TokenModel::query()->ownedBy($owner),
            $reason,
            fn (RefreshToken $row): bool => $currentAccessReference !== null && $row->access_reference === $currentAccessReference,
        );

        /** @var Collection<int, RefreshToken> $sessions */
        $sessions = TokenModel::query()
            ->ownedBy($owner)
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

        return $sealed + $revoked;
    }
}
