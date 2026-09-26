<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\SessionRevoked;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Revoke a single session (refresh-token row). Idempotent: revoking an already
 * revoked row is a no-op — no duplicate access-token denial, no duplicate event.
 */
final class RevokeSessionAction
{
    public function __construct(
        private readonly AccessTokenRevoker $revoker,
    ) {}

    public function execute(RefreshToken $session, RevocationReason $reason = RevocationReason::Manual): bool
    {
        $claimed = TokenModel::query()
            ->whereKey($session->getKey())
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => CarbonImmutable::now(),
                'revoked_reason' => $reason->value,
            ]);

        if ($claimed === 0) {
            return false;
        }

        if ($session->access_reference !== null) {
            $this->revoker->revoke($session->access_reference);
        }

        Event::dispatch(new SessionRevoked(
            $session->getKey(),
            $session->family_id,
            $session->owner_type,
            $session->owner_id,
            $reason,
            $session->access_reference,
        ));

        return true;
    }
}
