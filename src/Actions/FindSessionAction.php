<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Resolve a session by its family id — the stable session identifier that
 * survives rotation (a row id changes on every refresh). Returns the family's
 * newest active row, or null when the id is malformed, names no live family, or
 * belongs to another owner.
 */
final class FindSessionAction
{
    public function execute(Authenticatable&Model $owner, string $familyId): ?RefreshToken
    {
        // Checked before the query: `family_id` is a uuid column and a strict engine
        // rejects a malformed literal with a raw QueryException.
        if (! Str::isUuid($familyId)) {
            return null;
        }

        return TokenModel::query()
            ->ownedBy($owner)
            ->forFamily($familyId)
            ->active()
            ->latest()
            ->latest('id')
            ->first();
    }
}
