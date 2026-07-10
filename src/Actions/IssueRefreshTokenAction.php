<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenIssued;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Mint a new opaque refresh token: generate a high-entropy plaintext, store only
 * its hash, root or inherit a family lineage, and return the plaintext once.
 *
 * When inheriting a family the action guards the theft response: the family must
 * exist for the owner and be alive before the insert, and — because reuse can fire
 * in the window around the insert — the just-inserted row is re-checked and
 * self-revoked if the family has since been killed, so a rotation replacement can
 * never outlive its family.
 */
final class IssueRefreshTokenAction
{
    public function __construct(
        private readonly TokenHasher $hasher,
    ) {}

    public function execute(Authenticatable $user, IssueContext $context): NewRefreshToken
    {
        $now = CarbonImmutable::now();

        if ($context->familyId !== null) {
            $this->assertFamilyIsInheritable($context->familyId, $user);
        }

        $plain = $this->hasher->generate();

        $token = TokenModel::make();
        $token->setAttribute(TokenModel::foreignKey(), $user->getAuthIdentifier());
        $token->token_hash = $this->hasher->hash($plain);
        $token->family_id = $context->familyId ?? (string) Str::uuid();
        $token->access_reference = $context->accessReference;
        $token->ip_address = $context->ipAddress;
        $token->user_agent = $context->userAgent;
        $token->expires_at = $this->expiresAt($now, $context->familyId);
        $token->save();

        // Reuse detection may have killed the family between the liveness check and
        // this insert (either ordering of insert-vs-family-revoke). If so, this
        // replacement must not survive the theft response — revoke it immediately.
        if ($context->familyId !== null && $this->familyHasReuse($context->familyId)) {
            $this->selfRevoke($token, $now);

            return new NewRefreshToken($plain, $token);
        }

        Event::dispatch(new RefreshTokenIssued($token->getKey()));

        return new NewRefreshToken($plain, $token);
    }

    /**
     * @throws InvalidTokenFamilyException
     */
    private function assertFamilyIsInheritable(string $familyId, Authenticatable $user): void
    {
        $ownedByUser = TokenModel::query()
            ->where('family_id', $familyId)
            ->where(TokenModel::foreignKey(), $user->getAuthIdentifier())
            ->exists();

        if (! $ownedByUser) {
            throw InvalidTokenFamilyException::unknownForOwner($familyId);
        }

        if ($this->familyHasReuse($familyId)) {
            throw InvalidTokenFamilyException::reuseRevoked($familyId);
        }
    }

    private function familyHasReuse(string $familyId): bool
    {
        return TokenModel::query()
            ->where('family_id', $familyId)
            ->where('revoked_reason', RevocationReason::ReuseDetected->value)
            ->exists();
    }

    private function selfRevoke(RefreshToken $token, CarbonImmutable $now): void
    {
        TokenModel::query()
            ->whereKey($token->getKey())
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => $now,
                'revoked_reason' => RevocationReason::ReuseDetected->value,
            ]);

        $token->revoked_at = $now;
        $token->revoked_reason = RevocationReason::ReuseDetected;
    }

    /**
     * The sliding TTL, clamped for a rotation replacement to the family root's age
     * plus the absolute TTL so repeated rotation cannot extend a session forever.
     */
    private function expiresAt(CarbonImmutable $now, ?string $familyId): CarbonImmutable
    {
        $expiresAt = $now->addSeconds($this->ttl());

        if ($familyId === null) {
            return $expiresAt;
        }

        $absolute = $this->absoluteTtl();

        if ($absolute <= 0) {
            return $expiresAt;
        }

        $root = TokenModel::query()
            ->where('family_id', $familyId)
            ->orderBy('created_at')
            ->orderBy('id')
            ->first();

        if ($root === null) {
            return $expiresAt;
        }

        $cap = $root->created_at->toImmutable()->addSeconds($absolute);

        return $cap->lessThan($expiresAt) ? $cap : $expiresAt;
    }

    private function ttl(): int
    {
        $ttl = config('refresh-tokens.ttl', 2_592_000);

        return is_int($ttl) && $ttl > 0 ? $ttl : 2_592_000;
    }

    private function absoluteTtl(): int
    {
        $ttl = config('refresh-tokens.absolute_ttl', 7_776_000);

        return is_int($ttl) && $ttl > 0 ? $ttl : 0;
    }
}
