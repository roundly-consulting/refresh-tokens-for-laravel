<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use SensitiveParameter;

/**
 * The crown jewel: atomically redeem (rotate) a refresh token with anti-double-spend
 * and reuse detection. Of N concurrent redemptions of the same token, exactly one
 * wins; presenting an already-rotated token revokes the whole family.
 *
 * Failure modes collapse to a single indistinguishable outcome — `null` — so a caller
 * cannot tell unknown from expired from revoked from race-lost.
 */
final class RedeemRefreshTokenAction
{
    public function __construct(
        private readonly TokenHasher $hasher,
        private readonly RevokeTokenFamilyAction $revokeFamily,
    ) {}

    public function execute(#[SensitiveParameter] string $plain): ?RedemptionResult
    {
        $row = TokenModel::query()
            ->where('token_hash', $this->hasher->hash($plain))
            ->first();

        if ($row === null) {
            return null;
        }

        $now = CarbonImmutable::now();

        // Not usable: either revoked (a reuse signal unless within grace) or merely
        // expired (no family revoke — just null).
        if (! $row->isUsable()) {
            if ($row->revoked_at !== null && ! $this->withinGrace($row->revoked_at, $now)) {
                $this->revokeFamily->execute($row);
            }

            return null;
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

            if ($fresh !== null && $fresh->revoked_at !== null && $this->withinGrace($fresh->revoked_at, $now)) {
                return null; // benign single-flight retry within grace
            }

            $this->revokeFamily->execute($row);

            return null;
        }

        // Winner: reflect the claim on the in-memory row.
        $row->revoked_at = $now;
        $row->revoked_reason = RevocationReason::Rotated;

        $user = $row->owner;

        if (! $user instanceof Authenticatable) {
            return null;
        }

        return new RedemptionResult($user, $row->family_id, $row);
    }

    private function withinGrace(CarbonImmutable $revokedAt, CarbonImmutable $now): bool
    {
        $grace = $this->grace();

        if ($grace <= 0) {
            return false;
        }

        return $now->lessThanOrEqualTo($revokedAt->addSeconds($grace));
    }

    private function grace(): int
    {
        $grace = config('refresh-tokens.rotation.grace', 0);

        return is_int($grace) && $grace > 0 ? $grace : 0;
    }
}
