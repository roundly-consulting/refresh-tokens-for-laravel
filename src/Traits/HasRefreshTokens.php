<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Traits;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\Contracts\SessionManager;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use SensitiveParameter;

/**
 * Give any Authenticatable model (a user, a client, an admin …) its refresh
 * tokens and active sessions, plus idiomatic `$owner->…()` session verbs that
 * read as the owner acting on itself. Tokens hang off the polymorphic `owner`
 * relation, so several owner models share the one table without colliding.
 *
 * @mixin Model
 *
 * @phpstan-require-extends Model
 *
 * @phpstan-require-implements Authenticatable
 */
trait HasRefreshTokens
{
    /**
     * @return MorphMany<RefreshToken, $this>
     */
    public function refreshTokens(): MorphMany
    {
        return $this->morphMany(TokenModel::class(), 'owner');
    }

    /**
     * Active (not revoked, not expired) refresh tokens — the owner's live sessions.
     *
     * @return MorphMany<RefreshToken, $this>
     */
    public function sessions(): MorphMany
    {
        return $this->refreshTokens()
            ->whereNull('revoked_at')
            ->where('expires_at', '>', CarbonImmutable::now());
    }

    /**
     * Issue a refresh token for this owner (plaintext returned once).
     */
    public function issueRefreshToken(IssueContext $context): NewRefreshToken
    {
        return app(RefreshTokenManager::class)->issue($this, $context);
    }

    /**
     * The active row of one of this owner's sessions, addressed by family id.
     */
    public function findSession(string $familyId): ?RefreshToken
    {
        return app(SessionManager::class)->findSession($this, $familyId);
    }

    /**
     * Revoke one of this owner's sessions by family id; false when nothing was revoked.
     */
    public function revokeSession(string $familyId, RevocationReason $reason = RevocationReason::Logout): bool
    {
        return app(SessionManager::class)->revokeSession($this, $familyId, $reason);
    }

    /**
     * Revoke every active session for this owner — the canonical "log out
     * everywhere" reaction to a credential change. Returns the count revoked.
     */
    public function revokeAllSessions(RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return app(RefreshTokenManager::class)->revokeAllFor($this, $reason);
    }

    /**
     * Revoke every active session except the one holding the current access
     * reference. Returns the count revoked.
     */
    public function revokeOtherSessions(#[SensitiveParameter] ?string $currentAccessReference): int
    {
        return app(SessionManager::class)->revokeOthers($this, $currentAccessReference);
    }
}
