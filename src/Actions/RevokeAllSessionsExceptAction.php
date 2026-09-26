<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Revoke every active session of an owner except one, addressed by family id
 * ("log out my other devices"). A null — or malformed, hence matching nothing —
 * `$keepFamilyId` revokes them all: failing closed is the safe reading of an
 * unrecognisable "current session". The kept family is compared in PHP, never in
 * SQL, so a malformed id cannot reach a strict engine's uuid column. Sessions caught
 * mid-rotation are sealed first ({@see SealPendingRotationsAction}). Returns the
 * number of sessions ended.
 */
final class RevokeAllSessionsExceptAction
{
    public function __construct(
        private readonly RevokeSessionAction $revokeSession,
        private readonly SealPendingRotationsAction $seal,
    ) {}

    public function execute(
        Authenticatable&Model $owner,
        ?string $keepFamilyId,
        RevocationReason $reason = RevocationReason::LogoutAll,
    ): int {
        $keep = $keepFamilyId !== null ? strtolower($keepFamilyId) : null;

        $revoked = $this->seal->execute(
            TokenModel::query()->ownedBy($owner),
            $reason,
            fn (RefreshToken $row): bool => $keep !== null && strtolower($row->family_id) === $keep,
        );

        /** @var Collection<int, RefreshToken> $sessions */
        $sessions = TokenModel::query()
            ->ownedBy($owner)
            ->active()
            ->get();

        foreach ($sessions as $session) {
            if ($keep !== null && strtolower($session->family_id) === $keep) {
                continue;
            }

            if ($this->revokeSession->execute($session, $reason)) {
                $revoked++;
            }
        }

        return $revoked;
    }
}
