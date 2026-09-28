<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use SensitiveParameter;

/**
 * One-call rotation: redeem the presented token, then issue a same-family replacement
 * that inherits the session (family timestamps, device/geo columns, `meta`).
 *
 * Null on a failed redeem (unknown, expired, revoked, race lost) and whenever reuse
 * detection or a revoke ended the family between the redeem and the issue — the
 * redeemed token is spent and there is no live lineage to hand back.
 */
final readonly class RotateRefreshTokenAction
{
    public function __construct(
        private RedeemRefreshTokenAction $redeem,
        private IssueRefreshTokenAction $issue,
    ) {}

    public function execute(#[SensitiveParameter] string $plain, ?RotationContext $context = null): ?RotationResult
    {
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
