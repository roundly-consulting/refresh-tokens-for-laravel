<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Traits;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Give a user model its refresh tokens and active sessions.
 *
 * @mixin Model
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
}
