<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Database\Eloquent\Builder;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;
use RoundlyConsulting\PackageToolkit\Support\ModelResolver;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

/**
 * The single resolution point for the storage seam: the model configured at
 * `refresh-tokens.model`, the table it lives in, and the owner key's type.
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

    /**
     * The primary-key type shared by every owner model, driving the `owner_id`
     * column shape.
     *
     * `bigint`, `uuid` or `ulid` (case-insensitive); absent or null reads as
     * `bigint`. Anything else — including `id`, this package's pre-toolkit
     * spelling — throws the toolkit's `InvalidConfigurationException`, so an env
     * typo stops the app instead of silently keying a uuid/ulid owner with bigints.
     */
    public static function keyType(): KeyType
    {
        return KeyType::fromConfig('refresh-tokens.key_type');
    }
}
