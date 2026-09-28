<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use SensitiveParameter;

/**
 * Revoke a token by its plaintext — logout with the token in hand. The plaintext is
 * looked up by its at-rest digest, never stored or compared raw. Idempotent: an
 * unknown or already revoked token revokes nothing and returns false.
 */
final readonly class RevokeRefreshTokenAction
{
    public function __construct(
        private TokenHasher $hasher,
        private RevokeSessionAction $revokeSession,
    ) {}

    public function execute(#[SensitiveParameter] string $plain, RevocationReason $reason = RevocationReason::Logout): bool
    {
        $row = TokenModel::query()
            ->where('token_hash', $this->hasher->hash($plain))
            ->first();

        return $row !== null && $this->revokeSession->execute($row, $reason);
    }
}
