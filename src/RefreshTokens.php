<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Actions\EnrichSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\FindSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\IssueRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\ListSessionsAction;
use RoundlyConsulting\RefreshTokens\Actions\RedeemRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeAllSessionsAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeAllSessionsExceptAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeOtherSessionsAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeSessionByFamilyAction;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\Contracts\SessionManager;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\PendingIssue;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use SensitiveParameter;

/**
 * The package's primary entry point: a single stateless service implementing both
 * the {@see RefreshTokenManager} and {@see SessionManager} contracts and exposed
 * via the {@see Facades\RefreshToken} facade.
 *
 * Actions are resolved fresh from the container per call so host rebindings (e.g.
 * a real {@see AccessTokenRevoker}) and
 * `Event::fake()` always take effect.
 */
final class RefreshTokens implements RefreshTokenManager, SessionManager
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function issue(Authenticatable&Model $owner, IssueContext $context): NewRefreshToken
    {
        return $this->app->make(IssueRefreshTokenAction::class)->execute($owner, $context);
    }

    /**
     * Begin a fluent issue for the given owner.
     */
    public function for(Authenticatable&Model $owner): PendingIssue
    {
        return new PendingIssue($this, $owner);
    }

    public function redeem(#[SensitiveParameter] string $plain, ?string $ownerType = null): ?RedemptionResult
    {
        return $this->app->make(RedeemRefreshTokenAction::class)->execute($plain, $ownerType);
    }

    public function rotate(#[SensitiveParameter] string $plain, ?RotationContext $context = null): ?RotationResult
    {
        $result = $this->redeem($plain, $context?->ownerType);

        if ($result === null) {
            return null;
        }

        try {
            $replacement = $this->issue($result->user, new IssueContext(
                ipAddress: $context?->ipAddress,
                userAgent: $context?->userAgent,
                accessReference: $context?->accessReference,
                familyId: $result->familyId,
                ttl: $context?->ttl,
                meta: $context?->meta,
            ));
        } catch (InvalidTokenFamilyException) {
            // Reuse detection killed the family between the redeem and the issue: the
            // redeemed token is spent and there is no live lineage to extend.
            return null;
        }

        // The replacement was born into a family that reuse detection killed around
        // the insert: it is already revoked, so there is no live session to hand back.
        if ($replacement->token->revoked_reason === RevocationReason::ReuseDetected) {
            return null;
        }

        return new RotationResult($result->user, $replacement, $result->familyId);
    }

    /**
     * Revoke by plaintext (logout with token in hand) or by session row. Idempotent.
     * The reason defaults to `Logout` for a plaintext and `Manual` for a row.
     */
    public function revoke(#[SensitiveParameter] RefreshToken|string $token, ?RevocationReason $reason = null): void
    {
        if (is_string($token)) {
            $row = TokenModel::query()
                ->where('token_hash', $this->app->make(TokenHasher::class)->hash($token))
                ->first();

            if ($row !== null) {
                $this->app->make(RevokeSessionAction::class)->execute($row, $reason ?? RevocationReason::Logout);
            }

            return;
        }

        $this->app->make(RevokeSessionAction::class)->execute($token, $reason ?? RevocationReason::Manual);
    }

    public function revokeAllFor(Authenticatable&Model $owner, RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return $this->app->make(RevokeAllSessionsAction::class)->execute($owner, $reason);
    }

    /**
     * @return Collection<int, RefreshToken>
     */
    public function listFor(Authenticatable&Model $owner): Collection
    {
        return $this->app->make(ListSessionsAction::class)->execute($owner);
    }

    public function findSession(Authenticatable&Model $owner, string $familyId): ?RefreshToken
    {
        return $this->app->make(FindSessionAction::class)->execute($owner, $familyId);
    }

    public function revokeSession(Authenticatable&Model $owner, string $familyId, RevocationReason $reason = RevocationReason::Logout): bool
    {
        return $this->app->make(RevokeSessionByFamilyAction::class)->execute($owner, $familyId, $reason);
    }

    public function revokeAllExcept(Authenticatable&Model $owner, ?string $keepFamilyId, RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return $this->app->make(RevokeAllSessionsExceptAction::class)->execute($owner, $keepFamilyId, $reason);
    }

    public function revokeOthers(
        Authenticatable&Model $owner,
        #[SensitiveParameter] ?string $currentAccessReference,
        RevocationReason $reason = RevocationReason::LogoutAll,
    ): int {
        return $this->app->make(RevokeOtherSessionsAction::class)
            ->execute($owner, $currentAccessReference, $reason);
    }

    public function revokeAll(Authenticatable&Model $owner, RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return $this->revokeAllFor($owner, $reason);
    }

    public function enrich(RefreshToken|int|string $session, DeviceData $device, ?LocationData $location = null): void
    {
        $this->app->make(EnrichSessionAction::class)->execute($session, $device, $location);
    }
}
