<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

use SensitiveParameter;

/**
 * Input for issuing a new refresh token. Every field is optional; `familyId` is
 * only set when issuing a rotation replacement that inherits the redeemed token's
 * family lineage.
 */
final readonly class IssueContext
{
    public function __construct(
        public ?string $ipAddress = null,
        public ?string $userAgent = null,
        #[SensitiveParameter] public ?string $accessReference = null,
        public ?string $familyId = null,
    ) {}
}
