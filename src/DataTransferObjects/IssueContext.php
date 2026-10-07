<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

use SensitiveParameter;

/**
 * Input for issuing a new refresh token. Every field is optional.
 *
 * - `familyId` inherits an existing family the owner already holds (a rotation
 *   replacement). The newest row of that family is the inheritance source: its
 *   `family_started_at`, `absolute_expires_at`, `meta` and device/geo columns are
 *   carried forward, and `ipAddress`/`userAgent` fall back to it when null here.
 * - `newFamilyId` roots a NEW family under a caller-chosen UUID (e.g. a session id
 *   already embedded in the access token). Mutually exclusive with `familyId`.
 * - `ttl` (≥ 1 s) overrides `refresh-tokens.ttl` for this token; `absoluteTtl`
 *   (≥ 0 s, 0 = uncapped) overrides `refresh-tokens.absolute_ttl` and is honoured
 *   only when rooting a family — an inherited family keeps its stored cap.
 * - `meta` is host session metadata stored as JSON (e.g. guard, auth method,
 *   `amr`, `auth_time`, device name). On inherit it is merged over the source
 *   row's meta (keys here win). It is readable by anyone who can read the table
 *   and is serialised with the model: NEVER put secrets in it.
 * - `accessReference` (e.g. the access token's jti) is at most 64 bytes — the
 *   column's width; a longer one throws before any query.
 */
final readonly class IssueContext
{
    /**
     * @param  array<string, mixed>|null  $meta
     */
    public function __construct(
        public ?string $ipAddress = null,
        public ?string $userAgent = null,
        #[SensitiveParameter] public ?string $accessReference = null,
        public ?string $familyId = null,
        public ?string $newFamilyId = null,
        public ?int $ttl = null,
        public ?int $absoluteTtl = null,
        public ?array $meta = null,
    ) {}
}
