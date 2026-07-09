<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Traits;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\Contracts\SessionManager;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use SensitiveParameter;

/**
 * Give a user model its refresh tokens and active sessions, plus idiomatic
 * `$user->…()` session verbs that read as the user acting on itself.
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
     * @return HasMany<RefreshToken, $this>
     */
    public function refreshTokens(): HasMany
    {
        return $this->hasMany(TokenModel::class(), TokenModel::foreignKey());
    }

    /**
     * Active (not revoked, not expired) refresh tokens — the user's live sessions.
     *
     * @return HasMany<RefreshToken, $this>
     */
    public function sessions(): HasMany
    {
        return $this->refreshTokens()
            ->whereNull('revoked_at')
            ->where('expires_at', '>', CarbonImmutable::now());
    }

    /**
     * Issue a refresh token for this user (plaintext returned once).
     */
    public function issueRefreshToken(IssueContext $context): NewRefreshToken
    {
        return app(RefreshTokenManager::class)->issue($this, $context);
    }

    /**
     * Revoke every active session for this user — the canonical "log out
     * everywhere" reaction to a credential change. Returns the count revoked.
     */
    public function revokeAllSessions(): int
    {
        return app(RefreshTokenManager::class)->revokeAllFor($this);
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
