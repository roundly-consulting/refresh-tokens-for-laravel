<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Enums;

use Illuminate\Database\Schema\Blueprint;
use RoundlyConsulting\Enums\Helpers;

/**
 * The primary-key type of the host's user model, driving the refresh-tokens
 * foreign-key column so UUID/ULID-keyed user models are supported alongside the
 * default auto-incrementing bigint.
 */
enum UserKeyType: string
{
    use Helpers;

    case Id = 'id';
    case Uuid = 'uuid';
    case Ulid = 'ulid';

    /**
     * Add the foreign-key column of this key type to the table.
     */
    public function foreignColumn(Blueprint $table, string $foreignKey): void
    {
        match ($this) {
            self::Id => $table->unsignedBigInteger($foreignKey)->index(),
            self::Uuid => $table->uuid($foreignKey)->index(),
            self::Ulid => $table->ulid($foreignKey)->index(),
        };
    }
}
