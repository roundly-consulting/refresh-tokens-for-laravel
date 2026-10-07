<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * The theft response: close the family's session even when it is caught mid-rotation,
 * revoke every still-active member, deny each member's access token, and fire the
 * reuse-detected signal once, counting every session it ended.
 *
 * @internal a building block of reuse detection in {@see RedeemRefreshTokenAction} and
 *           {@see RevokeRefreshTokenAction} — never called on its own; reuse is detected by
 *           presenting a spent token (to redeem it, or to log out with it).
 */
final readonly class RevokeTokenFamilyAction
{
    public function __construct(
        private AccessTokenRevoker $revoker,
        private SealPendingRotationsAction $seal,
    ) {}

    public function execute(RefreshToken $token): int
    {
        $now = CarbonImmutable::now();

        // A family caught mid-rotation has no live row: its newest row is claimed by a
        // refresh whose replacement is not inserted yet. That pending row still holds the
        // session — its access token is live — so it is sealed as reuse first, like any
        // revoke seals it: its access token denied, its end announced, and it counts
        // towards the reuse signal. Whether the alert fired used to hinge on whether the
        // replacement had landed yet. Sealing first also puts the verdict on the family
        // before the scan below.
        $revoked = $this->seal->execute(
            TokenModel::query()->forFamily($token->family_id),
            RevocationReason::ReuseDetected,
        );

        // The verdict goes on the family BEFORE the scan looks. The family may be
        // mid-rotation — its newest row claimed by a refresh whose replacement is not
        // inserted yet — so the scan can find nothing live. Flagging the re-presented row
        // (when the seal did not already relabel it) first means a replacement inserted before the scan is swept by it, and one
        // inserted after it sees the flag in its own dead-family check (before and after
        // its insert). Flagged after the scan instead, a replacement landing in between
        // passed every check and survived the reuse.
        TokenModel::query()
            ->whereKey($token->getKey())
            ->where('revoked_reason', RevocationReason::Rotated->value)
            ->update(['revoked_reason' => RevocationReason::ReuseDetected->value]);

        // Re-scan until a pass revokes nothing: a rotation replacement issued into
        // this family *after* an earlier snapshot (the reuse-detection race) becomes
        // visible on the next pass and is caught, so no fresh token survives the kill.
        do {
            /** @var Collection<int, RefreshToken> $members */
            $members = TokenModel::query()
                ->where('family_id', $token->family_id)
                ->whereNull('revoked_at')
                ->get();

            $revokedThisPass = 0;

            foreach ($members as $member) {
                $claimed = TokenModel::query()
                    ->whereKey($member->getKey())
                    ->whereNull('revoked_at')
                    ->update([
                        'revoked_at' => $now,
                        'revoked_reason' => RevocationReason::ReuseDetected->value,
                    ]);

                if ($claimed === 0) {
                    continue;
                }

                $revokedThisPass++;
                $revoked++;

                if ($member->access_reference !== null) {
                    $this->revoker->revoke($member->access_reference);
                }
            }
        } while ($revokedThisPass > 0);

        // Only signal on a real transition: re-presenting a token of an already-dead
        // family ends nothing, so it must not spam host alerting with empty reuse events.
        if ($revoked > 0) {
            Event::dispatch(new RefreshTokenReuseDetected(
                $token->family_id,
                $token->owner_type,
                $token->owner_id,
                $revoked,
            ));
        }

        return $revoked;
    }
}
