<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Tests\Fixtures;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use RoundlyConsulting\RefreshTokens\Traits\HasRefreshTokens;

/**
 * A second, isolated account type (an API client) with its own table, sharing
 * the one refresh-token table with {@see User} through the polymorphic owner.
 *
 * @property int $id
 * @property string|null $name
 */
final class Client extends Authenticatable
{
    /** @use HasFactory<ClientFactory> */
    use HasFactory;

    use HasRefreshTokens;

    protected $guarded = [];

    protected $table = 'clients';

    protected static function newFactory(): ClientFactory
    {
        return ClientFactory::new();
    }
}
