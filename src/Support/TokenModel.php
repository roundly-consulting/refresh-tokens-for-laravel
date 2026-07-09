<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Database\Eloquent\Builder;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

/**
 * Resolves the configured refresh-token model class so hosts can swap in a
 * subclass via `refresh-tokens.model` and have every query honour it.
 */
final class TokenModel
{
    /**
     * @return class-string<RefreshToken>
     */
    public static function class(): string
    {
        $class = config('refresh-tokens.model', RefreshToken::class);

        if (is_string($class) && (is_a($class, RefreshToken::class, true))) {
            return $class;
        }

        return RefreshToken::class;
    }

    public static function make(): RefreshToken
    {
        $class = self::class();

        return new $class;
    }

    /**
     * @return Builder<RefreshToken>
     */
    public static function query(): Builder
    {
        return self::make()->newQuery();
    }

    public static function foreignKey(): string
    {
        $key = config('refresh-tokens.foreign_key', 'user_id');

        return is_string($key) && $key !== '' ? $key : 'user_id';
    }
}
