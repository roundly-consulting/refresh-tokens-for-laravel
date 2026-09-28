<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Actions\FindSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\ListSessionsAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeAllSessionsAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeAllSessionsExceptAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeOtherSessionsAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeSessionByFamilyAction;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Testing\RecordingOwnerSessions;
use SensitiveParameter;

/**
 * One owner's device sessions — `RefreshTokens::sessions($user)`. A session is
 * addressed by its family id, which survives rotation (a row id changes on every
 * refresh).
 *
 * Owner-scoped throughout: another owner's family id is unknown here — `find()`
 * returns null and `revoke()` returns false without touching it.
 *
 * Not final: {@see RecordingOwnerSessions} extends it under `RefreshTokens::fake()`.
 */
readonly class OwnerSessions
{
    public function __construct(
        protected Container $container,
        public Authenticatable&Model $owner,
    ) {}

    /**
     * Active sessions (not revoked, not expired), newest first.
     *
     * @return Collection<int, RefreshToken>
     */
    public function all(): Collection
    {
        return $this->container->make(ListSessionsAction::class)->execute($this->owner);
    }

    /**
     * The active row of one of the owner's families; null when malformed, unknown, dead
     * or foreign.
     */
    public function find(string $familyId): ?RefreshToken
    {
        return $this->container->make(FindSessionAction::class)->execute($this->owner, $familyId);
    }

    /**
     * Revoke every active row of one of the owner's families (sealing it if caught
     * mid-rotation); false when nothing was revoked.
     */
    public function revoke(string $familyId, RevocationReason $reason = RevocationReason::Logout): bool
    {
        return $this->container->make(RevokeSessionByFamilyAction::class)->execute($this->owner, $familyId, $reason);
    }

    /**
     * Revoke every session except the one holding the current access reference (null =
     * all). Returns the count ended.
     */
    public function revokeOthers(
        #[SensitiveParameter] ?string $currentAccessReference,
        RevocationReason $reason = RevocationReason::LogoutAll,
    ): int {
        return $this->container->make(RevokeOtherSessionsAction::class)
            ->execute($this->owner, $currentAccessReference, $reason);
    }

    /**
     * Revoke every session except the given family (null = all). Returns the count ended.
     */
    public function revokeAllExcept(?string $keepFamilyId, RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return $this->container->make(RevokeAllSessionsExceptAction::class)
            ->execute($this->owner, $keepFamilyId, $reason);
    }

    /**
     * Revoke every session — "log out everywhere". Returns the count ended.
     */
    public function revokeAll(RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return $this->container->make(RevokeAllSessionsAction::class)->execute($this->owner, $reason);
    }
}
