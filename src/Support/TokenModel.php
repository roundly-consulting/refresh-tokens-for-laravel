<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Database\Eloquent\Builder;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;
use RoundlyConsulting\PackageToolkit\Support\ModelResolver;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

/**
 * The single resolution point for the storage seam: the model configured at
 * `refresh-tokens.model`, the table it lives in, the owner foreign key, and that
 * key's type.
 *
 * The model lookup wraps the toolkit's {@see ModelResolver} (which validates the
 * configured value really is an Eloquent model) and narrows the result to this
 * package's own base class — every call site uses `RefreshToken`'s own API
 * (`isUsable()`, the scopes, the enum casts), so a real model that is not a
 * `RefreshToken` falls back to the packaged one rather than fataling later.
 */
final class TokenModel
{
    /**
     * @return class-string<RefreshToken>
     */
    public static function class(): string
    {
        $model = ModelResolver::for('refresh-tokens.model', RefreshToken::class);

        return is_a($model, RefreshToken::class, true) ? $model : RefreshToken::class;
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

    public static function table(): string
    {
        $table = config('refresh-tokens.table', 'refresh_tokens');

        return is_string($table) && $table !== '' ? $table : 'refresh_tokens';
    }

    public static function foreignKey(): string
    {
        $key = config('refresh-tokens.foreign_key', 'user_id');

        return is_string($key) && $key !== '' ? $key : 'user_id';
    }

    /**
     * The host user model's primary-key type, driving the foreign-key column shape.
     *
     * Misconfiguration never throws: an unrecognized value silently falls back to
     * bigint, so a one-line env typo can't break the schema. The value `id` — what
     * this package shipped before it moved onto the toolkit's key type — is still
     * accepted, as the toolkit keeps it as an alias for `bigint`.
     */
    public static function keyType(): KeyType
    {
        return KeyType::fromConfig('refresh-tokens.key_type');
    }
}
