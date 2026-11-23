<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionAttempt;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\Enums\RedemptionFailure;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenRedeemed;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\RotationGrace;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use SensitiveParameter;

/**
 * The crown jewel: atomically redeem (rotate) a refresh token with anti-double-spend
 * and reuse detection. Of N concurrent redemptions of the same token, exactly one
 * wins; presenting an already-rotated token revokes the whole family.
 *
 * A failure is `Refused` — unknown, expired, revoked, reused, race lost, another owner
 * type, all alike — except one benign case, `Superseded`: the token was revoked as
 * `Rotated` inside `rotation.grace` (a late duplicate, or a concurrent refresh that won
 * the claim) and its family still lives (a usable token, or the in-grace rotation that
 * is minting one). Superseded is no oracle: only a holder of a token rotated seconds
 * ago can see it, and it tells them only that their own session is alive — which the
 * concurrent refresh that rotated it already told them. Reuse detection is untouched:
 * outside the grace a spent token revokes its family and fires the reuse event.
 *
 * Given an `$ownerType` (an owner morph class) the lookup is scoped to it: a token
 * belonging to another owner type is invisible — refused, not claimed, no family
 * revoke, no event. Presenting a user's token at a client-only refresh endpoint
 * must neither burn the user's session nor count as reuse.
 */
final readonly class AttemptRedemptionAction
{
    public function __construct(
        private TokenHasher $hasher,
        private RevokeTokenFamilyAction $revokeFamily,
    ) {}

    public function execute(#[SensitiveParameter] string $plain, ?string $ownerType = null): RedemptionAttempt
    {
        $lookup = TokenModel::query()->where('token_hash', $this->hasher->hash($plain));

        if ($ownerType !== null) {
            $lookup->where('owner_type', $ownerType);
        }

        $row = $lookup->first();

        if ($row === null) {
            return RedemptionAttempt::failed(RedemptionFailure::Refused);
        }

        $now = CarbonImmutable::now();

        // Not usable: either revoked (a reuse signal unless within grace) or merely
        // expired (no family revoke — just refused).
        if (! $row->isUsable()) {
            if ($row->revoked_at === null) {
                return RedemptionAttempt::failed(RedemptionFailure::Refused);
            }

            if (! RotationGrace::covers($row->revoked_at, $now)) {
                $this->revokeFamily->execute($row);

                return RedemptionAttempt::failed(RedemptionFailure::Refused);
            }

            return RedemptionAttempt::failed($this->benignFailure($row, $now)); // late duplicate
        }

        // Atomic claim: the `WHERE revoked_at IS NULL` predicate is the mutex the DB
        // serialises — no transaction, no row lock, works on pgsql and sqlite alike.
        $claimed = TokenModel::query()
            ->whereKey($row->getKey())
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => $now,
                'revoked_reason' => RevocationReason::Rotated->value,
            ]);

        if ($claimed === 0) {
            // A concurrent redemption already won the race.
            $fresh = TokenModel::query()->whereKey($row->getKey())->first();

            if ($fresh !== null && $fresh->revoked_at !== null && RotationGrace::covers($fresh->revoked_at, $now)) {
                return RedemptionAttempt::failed($this->benignFailure($fresh, $now)); // single-flight retry
            }

            $this->revokeFamily->execute($row);

            return RedemptionAttempt::failed(RedemptionFailure::Refused);
        }

        // Winner: reflect the claim on the in-memory row.
        $row->revoked_at = $now;
        $row->revoked_reason = RevocationReason::Rotated;

        $owner = $row->owner;

        // The row was claimed but its owner is gone (e.g. the owner was deleted after
        // issue). The token stays revoked; there is nothing to hand back and no
        // successful-redeem signal to emit.
        if (! $owner instanceof Authenticatable) {
            return RedemptionAttempt::failed(RedemptionFailure::Refused);
        }

        Event::dispatch(new RefreshTokenRedeemed($row->getKey(), $row->family_id, $row->owner_type, $row->owner_id));

        return RedemptionAttempt::won(new RedemptionResult($owner, $row->family_id, $row));
    }

    /**
     * A token revoked inside the grace: superseded only when a rotation spent it (never a
     * logout, a security response or any other revoke) and its family still lives.
     * Nothing is revoked and no event fires either way, as before.
     */
    private function benignFailure(RefreshToken $row, CarbonImmutable $now): RedemptionFailure
    {
        return $row->revoked_reason === RevocationReason::Rotated && $this->familyLives($row, $now)
            ? RedemptionFailure::Superseded
            : RedemptionFailure::Refused;
    }

    /**
     * Whether the row's family (scoped to its owner) still holds the session: a usable
     * token, or a rotation in flight — its newest row claimed as `Rotated` inside the
     * grace, unexpired, its replacement not inserted yet.
     */
    private function familyLives(RefreshToken $row, CarbonImmutable $now): bool
    {
        if ($this->lineage($row)->whereNull('revoked_at')->where('expires_at', '>', $now)->exists()) {
            return true;
        }

        $newest = $this->lineage($row)->orderByDesc('id')->first();

        return $newest !== null
            && $newest->revoked_reason === RevocationReason::Rotated
            && $newest->revoked_at !== null
            && $newest->expires_at->greaterThan($now)
            && RotationGrace::covers($newest->revoked_at, $now);
    }

    /**
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
