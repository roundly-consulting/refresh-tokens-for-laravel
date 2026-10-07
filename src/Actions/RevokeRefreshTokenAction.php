<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\RotationGrace;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use SensitiveParameter;

/**
 * Revoke a token by its plaintext — logout with the token in hand. The plaintext is
 * looked up by its at-rest digest, never stored or compared raw.
 *
 * A token already **rotated** no longer holds the session: it lives on in the row it
 * was rotated into. Presenting it is the same theft signal {@see RedeemRefreshTokenAction}
 * acts on, so it gets the same response — the whole family is revoked as
 * `ReuseDetected` and `RefreshTokenReuseDetected` fires. Inside `rotation.grace` (a
 * benign single-flight race with the client's own refresh) the lineage is ended with
 * the caller's `$reason` instead, with no reuse signal. Either way a session caught
 * mid-rotation is sealed, so the in-flight replacement is refused.
 *
 * Returns true when the call ended a live session; false for an unknown token or one
 * whose session had already ended — revoked, or expired unused (idempotent).
 */
final readonly class RevokeRefreshTokenAction
{
    public function __construct(
        private TokenHasher $hasher,
        private RevokeSessionAction $revokeSession,
        private RevokeTokenFamilyAction $revokeFamily,
        private SealPendingRotationsAction $seal,
    ) {}

    public function execute(#[SensitiveParameter] string $plain, RevocationReason $reason = RevocationReason::Logout): bool
    {
        $row = TokenModel::query()
            ->where('token_hash', $this->hasher->hash($plain))
            ->first();

        if ($row === null) {
            return false;
        }

        // Expired unused: its session already ended, so there is nothing to end — no
        // claim, no access-token denial, no event. A spent (rotated) expired token still
        // takes the path below: its session lives on in the row it was rotated into.
        if ($row->revoked_at === null && ! $row->expires_at->isFuture()) {
            return false;
        }

        if (! $this->wasRotated($row) && $this->revokeSession->execute($row, $reason)) {
            return true;
        }

        // Rotated before the lookup, or by a refresh racing this logout between the
        // lookup and the claim: re-read, so the lineage it was rotated into is ended.
        $row = TokenModel::query()->whereKey($row->getKey())->first();

        return $row !== null && $this->wasRotated($row) && $this->endRotatedLineage($row, $reason);
    }

    private function wasRotated(RefreshToken $row): bool
    {
        return $row->revoked_at !== null && $row->revoked_reason === RevocationReason::Rotated;
    }

    /**
     * @param  RefreshToken  $row  a spent (rotated) row, freshly read
     */
    private function endRotatedLineage(RefreshToken $row, RevocationReason $reason): bool
    {
        $benign = $row->revoked_at !== null && RotationGrace::covers($row->revoked_at, CarbonImmutable::now());

        // Reuse: the theft response, exactly as a replay at redeem() gets it — it seals a
        // session caught mid-rotation itself.
        if (! $benign) {
            return $this->revokeFamily->execute($row) > 0;
        }

        // Seal first, like every session revoke: a replacement inserted before the seal
        // looks is caught by the sweep below, one inserted after finds its family sealed.
        $sealed = $this->seal->execute($this->lineage($row), $reason) > 0;

        /** @var Collection<int, RefreshToken> $live */
        $live = $this->lineage($row)->active()->get();

        $revoked = $sealed;

        foreach ($live as $member) {
            $revoked = $this->revokeSession->execute($member, $reason) || $revoked;
        }

        return $revoked;
    }

    /**
     * The row's family, scoped to its owner — a logout never reaches another owner's
     * session, even should a family id span two owners.
     *
     * @return Builder<RefreshToken>
     */
    private function lineage(RefreshToken $row): Builder
    {
        return TokenModel::query()
            ->forFamily($row->family_id)
            ->where('owner_type', $row->owner_type)
            ->where('owner_id', $row->owner_id);
    }
}
