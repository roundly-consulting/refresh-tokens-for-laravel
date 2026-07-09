<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Actions\EnrichSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\IssueRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\ListSessionsAction;
use RoundlyConsulting\RefreshTokens\Actions\RedeemRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeAllSessionsAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeOtherSessionsAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeSessionAction;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\Contracts\SessionManager;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
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

    public function issue(Authenticatable $user, IssueContext $context): NewRefreshToken
    {
        return $this->app->make(IssueRefreshTokenAction::class)->execute($user, $context);
    }

    /**
     * Begin a fluent issue for the given user.
     */
    public function for(Authenticatable $user): PendingIssue
    {
        return new PendingIssue($this, $user);
    }

    public function redeem(#[SensitiveParameter] string $plain): ?RedemptionResult
    {
        return $this->app->make(RedeemRefreshTokenAction::class)->execute($plain);
    }

    public function rotate(#[SensitiveParameter] string $plain, ?string $linkedTo = null): ?RotationResult
    {
        $result = $this->redeem($plain);

        if ($result === null) {
            return null;
        }

        $replacement = $this->issue($result->user, new IssueContext(
            accessReference: $linkedTo,
            familyId: $result->familyId,
        ));

        return new RotationResult($result->user, $replacement, $result->familyId);
    }

    /**
     * Revoke by plaintext (logout with token in hand) or by session row. Idempotent.
     */
    public function revoke(#[SensitiveParameter] RefreshToken|string $token): void
    {
        if (is_string($token)) {
            $row = TokenModel::query()
                ->where('token_hash', $this->app->make(TokenHasher::class)->hash($token))
                ->first();

            if ($row !== null) {
                $this->app->make(RevokeSessionAction::class)->execute($row, RevocationReason::Logout);
            }

            return;
        }

        $this->app->make(RevokeSessionAction::class)->execute($token, RevocationReason::Manual);
    }

    public function revokeAllFor(Authenticatable $user): int
    {
        return $this->app->make(RevokeAllSessionsAction::class)->execute($user, RevocationReason::LogoutAll);
    }

    /**
     * @return Collection<int, RefreshToken>
     */
    public function listFor(Authenticatable $user): Collection
    {
        return $this->app->make(ListSessionsAction::class)->execute($user);
    }

    public function revokeOthers(Authenticatable $user, ?string $currentAccessReference): int
    {
        return $this->app->make(RevokeOtherSessionsAction::class)
            ->execute($user, $currentAccessReference, RevocationReason::LogoutAll);
    }

    public function revokeAll(Authenticatable $user): int
    {
        return $this->revokeAllFor($user);
    }

    public function enrich(RefreshToken|int|string $session, DeviceData $device, ?LocationData $location = null): void
    {
        $this->app->make(EnrichSessionAction::class)->execute($session, $device, $location);
    }
}
