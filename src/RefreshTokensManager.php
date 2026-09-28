<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\RefreshTokens\Actions\IssueRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\PruneRefreshTokensAction;
use RoundlyConsulting\RefreshTokens\Actions\RedeemRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\RotateRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\OwnerSessions;
use RoundlyConsulting\RefreshTokens\Support\PendingIssue;
use RoundlyConsulting\RefreshTokens\Support\SessionHandle;
use RoundlyConsulting\RefreshTokens\Testing\RefreshTokensFake;
use SensitiveParameter;

/**
 * The package's public API and the root of the {@see RefreshTokens} facade. Inject it
 * for the facade-free form. Every method is a thin hop to an action resolved from the
 * container per call, so host rebindings (a real `AccessTokenRevoker`, an overridden
 * action) and `Event::fake()` always take effect.
 *
 * Not final: {@see RefreshTokensFake} extends it, so code that injects the manager
 * receives the fake under `RefreshTokens::fake()`.
 */
class RefreshTokensManager
{
    public function __construct(
        protected readonly Container $container,
    ) {}

    /**
     * Begin a fluent issue for the owner: `->fromRequest($r)->ttl(3600)->issue()`.
     */
    public function for(Authenticatable&Model $owner): PendingIssue
    {
        return new PendingIssue($this, $owner);
    }

    /**
     * Issue a new opaque token (plaintext returned once) for any Authenticatable model.
     */
    public function issue(Authenticatable&Model $owner, IssueContext $context): NewRefreshToken
    {
        return $this->container->make(IssueRefreshTokenAction::class)->execute($owner, $context);
    }

    /**
     * Atomically redeem (spend) a token. Null = unknown/expired/revoked/race-lost. With
     * `$ownerType` (a morph class), a token of another owner type is unknown and is not
     * consumed.
     */
    public function redeem(#[SensitiveParameter] string $plain, ?string $ownerType = null): ?RedemptionResult
    {
        return $this->container->make(RedeemRefreshTokenAction::class)->execute($plain, $ownerType);
    }

    /**
     * Redeem, then issue a same-family replacement in one call. Null on a failed redeem
     * or a family killed by reuse or a revoke mid-rotation.
     */
    public function rotate(#[SensitiveParameter] string $plain, ?RotationContext $context = null): ?RotationResult
    {
        return $this->container->make(RotateRefreshTokenAction::class)->execute($plain, $context);
    }

    /**
     * Revoke a token by its plaintext (logout with the token in hand). Idempotent; false
     * when no live token matched.
     */
    public function revoke(#[SensitiveParameter] string $plain, RevocationReason $reason = RevocationReason::Logout): bool
    {
        return $this->container->make(RevokeRefreshTokenAction::class)->execute($plain, $reason);
    }

    /**
     * The owner's device sessions: list, find and revoke them, scoped to this owner.
     */
    public function sessions(Authenticatable&Model $owner): OwnerSessions
    {
        return new OwnerSessions($this->container, $owner);
    }

    /**
     * One session row (a model or its key): enrich or revoke it.
     */
    public function session(RefreshToken|int|string $session): SessionHandle
    {
        return new SessionHandle($this->container, $session);
    }

    /**
     * Force-delete rows revoked or expired more than `$days` days ago (default
     * `refresh-tokens.prune.after`, never under one day). Returns the count deleted.
     */
    public function prune(?int $days = null): int
    {
        return $this->container->make(PruneRefreshTokensAction::class)->execute($days);
    }
}
