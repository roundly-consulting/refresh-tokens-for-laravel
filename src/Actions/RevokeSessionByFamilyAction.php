<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Revoke one session addressed by its family id. Every active row of the family
 * is revoked — a grace-window rotation can briefly leave two — each through
 * {@see RevokeSessionAction}, so each live access reference is denied once; a
 * session caught mid-rotation is sealed first ({@see SealPendingRotationsAction}).
 * Owner-scoped and uuid-validated: another owner's family or a malformed id
 * revokes nothing and returns false.
 */
final class RevokeSessionByFamilyAction
{
    public function __construct(
        private readonly RevokeSessionAction $revokeSession,
        private readonly SealPendingRotationsAction $seal,
    ) {}

    public function execute(
        Authenticatable&Model $owner,
        string $familyId,
        RevocationReason $reason = RevocationReason::Logout,
    ): bool {
        if (! Str::isUuid($familyId)) {
            return false;
        }

        $revoked = $this->seal->execute(TokenModel::query()->ownedBy($owner)->forFamily($familyId), $reason) > 0;

        /** @var Collection<int, RefreshToken> $rows */
        $rows = TokenModel::query()
            ->ownedBy($owner)
            ->forFamily($familyId)
            ->active()
            ->get();

        foreach ($rows as $row) {
            $revoked = $this->revokeSession->execute($row, $reason) || $revoked;
        }

        return $revoked;
    }
}
