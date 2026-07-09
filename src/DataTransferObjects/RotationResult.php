<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The outcome of a one-call rotation: the owning user, the freshly issued
 * replacement (plaintext once), and the family lineage it inherited.
 */
final readonly class RotationResult
{
    public function __construct(
        public Authenticatable $user,
        public NewRefreshToken $newRefreshToken,
        public string $redeemedFamilyId,
    ) {}
}
