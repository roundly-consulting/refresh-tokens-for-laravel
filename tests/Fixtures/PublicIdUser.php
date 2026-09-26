<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;
use RoundlyConsulting\RefreshTokens\Traits\HasRefreshTokens;

/**
 * An owner whose auth identifier is NOT its primary key (a host exposing a public id
 * to its guards). The polymorphic owner is keyed like every Eloquent morph — by the
 * model's key — so its tokens must still resolve back to this very row.
 *
 * @property int $id
 * @property string|null $name
 */
final class PublicIdUser extends Authenticatable
{
    use HasRefreshTokens;

    protected $guarded = [];

    protected $table = 'users';

    public function getAuthIdentifierName(): string
    {
        return 'name';
    }
}
