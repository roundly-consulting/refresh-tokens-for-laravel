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
 * The theft response: revoke every still-active member of a token's family, deny
 * each live member's access token, and fire the reuse-detected signal once.
 */
final class RevokeTokenFamilyAction
{
    public function __construct(
        private readonly AccessTokenRevoker $revoker,
    ) {}

    public function execute(RefreshToken $token): int
    {
        $now = CarbonImmutable::now();

        /** @var Collection<int, RefreshToken> $members */
        $members = TokenModel::query()
            ->where('family_id', $token->family_id)
            ->whereNull('revoked_at')
            ->get();

        $revoked = 0;

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

            $revoked++;

            if ($member->access_reference !== null) {
                $this->revoker->revoke($member->access_reference);
            }
        }

        Event::dispatch(new RefreshTokenReuseDetected(
            $token->family_id,
            $token->getAttribute(TokenModel::foreignKey()),
        ));

        return $revoked;
    }
}
