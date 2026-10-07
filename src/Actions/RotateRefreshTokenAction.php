<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Support\IssueGuard;
use SensitiveParameter;

/**
 * One-call rotation: redeem the presented token, then issue a same-family replacement
 * that inherits the session (family timestamps, device/geo columns, `meta`).
 *
 * Null on a failed redeem (unknown, expired, revoked, race lost) and whenever reuse
 * detection or a revoke ended the family between the redeem and the issue — the
 * redeemed token is spent and there is no live lineage to hand back. An invalid
 * context or config throws before the redeem, leaving the presented token usable.
 */
final readonly class RotateRefreshTokenAction
{
    public function __construct(
        private RedeemRefreshTokenAction $redeem,
        private IssueRefreshTokenAction $issue,
        private IssueGuard $guard,
    ) {}

    /**
     * @throws InvalidTokenConfigurationException on an invalid context or config — raised
     *                                            before the presented token is spent
     */
    public function execute(#[SensitiveParameter] string $plain, ?RotationContext $context = null): ?RotationResult
    {
        // The redeem's claim is never rolled back, so everything the issue would refuse
        // without a query is refused first: the presented token stays usable.
        $this->guard->assertCanIssue($context?->ttl, null, $context?->accessReference);

        $result = $this->redeem->execute($plain, $context?->ownerType);

        if ($result === null) {
            return null;
        }

        try {
            $replacement = $this->issue->execute($result->user, new IssueContext(
                ipAddress: $context?->ipAddress,
                userAgent: $context?->userAgent,
                accessReference: $context?->accessReference,
                familyId: $result->familyId,
                ttl: $context?->ttl,
                meta: $context?->meta,
            ));
        } catch (InvalidTokenFamilyException) {
            // Reuse detection or a revoke ended the family between the redeem and the
            // issue: the redeemed token is spent and there is no live lineage to extend.
            return null;
        }

        // The replacement was born into a family that reuse detection or a revoke ended
        // around the insert: it is already revoked, so there is no live session to hand back.
        if ($replacement->token->revoked_at !== null) {
            return null;
        }

        return new RotationResult($result->user, $replacement, $result->familyId);
    }
}
