<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

use SensitiveParameter;

/**
 * Optional input for a one-call rotation. `ownerType` scopes the redeem to one
 * owner morph class (a token of another type is treated as unknown and is NOT
 * consumed); the rest is handed to the replacement's {@see IssueContext}. Device
 * and geo columns, family timestamps and `meta` are always inherited from the
 * redeemed row; `ipAddress`/`userAgent` here replace the inherited values, and
 * `meta` here is merged over the inherited meta (keys here win).
 */
final readonly class RotationContext
{
    /**
     * @param  array<string, mixed>|null  $meta
     */
    public function __construct(
        public ?string $ownerType = null,
        public ?string $ipAddress = null,
        public ?string $userAgent = null,
        #[SensitiveParameter] public ?string $accessReference = null,
        public ?int $ttl = null,
        public ?array $meta = null,
    ) {}
}
