<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * The user's active sessions (not revoked, not expired), newest first.
 */
final class ListSessionsAction
{
    /**
     * @return Collection<int, RefreshToken>
     */
    public function execute(Authenticatable $user): Collection
    {
        return TokenModel::query()
            ->where(TokenModel::foreignKey(), $user->getAuthIdentifier())
            ->active()
            ->latest()
            ->latest('id')
            ->get();
    }
}
