<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * The owner's active sessions (not revoked, not expired), newest first.
 */
final readonly class ListSessionsAction
{
    /**
     * @return Collection<int, RefreshToken>
     */
    public function execute(Authenticatable&Model $owner): Collection
    {
        return TokenModel::query()
            ->ownedBy($owner)
            ->active()
            ->latest()
            ->latest('id')
            ->get();
    }
}
