<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use RoundlyConsulting\RefreshTokens\Actions\IssueRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\RotateRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use SensitiveParameter;

/**
 * The database-free half of an issue's validation: the per-issue lifetimes, the access
 * reference's width, and the config every issue falls back to (`ttl`, `absolute_ttl`,
 * `token_length`).
 *
 * {@see RotateRefreshTokenAction} runs it BEFORE its redeem: the redeem's claim is never
 * rolled back (un-claiming would reopen double-spend), so an input or config error raised
 * by the issue after it would spend the presented token with no replacement, and the
 * client's retry would count as reuse. {@see IssueRefreshTokenAction} runs it before its
 * first query.
 *
 * @internal shared by the issue and rotate actions — reach them through the facade.
 */
final readonly class IssueGuard
{
    public function __construct(
        private TokenHasher $hasher,
    ) {}

    /**
     * @throws InvalidTokenConfigurationException
     */
    public function assertCanIssue(?int $ttl, ?int $absoluteTtl, #[SensitiveParameter] ?string $accessReference): void
    {
        if ($ttl !== null && $ttl < 1) {
            throw InvalidTokenConfigurationException::invalidTtl($ttl);
        }

        if ($absoluteTtl !== null && $absoluteTtl < 0) {
            throw InvalidTokenConfigurationException::invalidAbsoluteTtl($absoluteTtl);
        }

        // Bytes, not characters: never more than the column holds on any engine. SQLite
        // would store a longer one; Postgres and strict MySQL raise a raw QueryException.
        if ($accessReference !== null && strlen($accessReference) > RefreshTokenBlueprint::ACCESS_REFERENCE_LENGTH) {
            throw InvalidTokenConfigurationException::accessReferenceTooLong(
                strlen($accessReference),
                RefreshTokenBlueprint::ACCESS_REFERENCE_LENGTH,
            );
        }

        // The config the issue falls back to, read now so a bad value throws here.
        if ($ttl === null) {
            Settings::ttl();
        }

        if ($absoluteTtl === null) {
            Settings::absoluteTtl();
        }

        $this->hasher->length();
    }
}
