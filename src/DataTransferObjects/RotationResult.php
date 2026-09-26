<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * The outcome of a one-call rotation: the owner (any Authenticatable model),
 * the freshly issued replacement (plaintext once), and the family lineage it
 * inherited.
 */
final readonly class RotationResult
{
    public function __construct(
        public Authenticatable&Model $user,
        public NewRefreshToken $newRefreshToken,
        public string $redeemedFamilyId,
    ) {}
}
