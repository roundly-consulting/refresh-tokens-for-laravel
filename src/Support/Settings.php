<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use RoundlyConsulting\PackageToolkit\Support\Config;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;

/**
 * Strict readers for the package's non-boolean settings. A key that is not set —
 * absent, null or blank (`''` or whitespace, what a host's `KEY=` gives) — takes its
 * default; a present value of the wrong shape throws
 * {@see InvalidTokenConfigurationException} naming the key — `'five'`, `'1.5'` or a
 * value out of range never silently becomes a number or the default.
 *
 * Callers read the value with a literal `config()` themselves and hand it in, so
 * the key stays visible to the config contract.
 *
 * @internal the package's own config wiring — hosts configure `config/refresh-tokens.php`.
 */
final class Settings
{
    /**
     * The sliding lifetime in seconds (`refresh-tokens.ttl`, at least 1).
     */
    public static function ttl(): int
    {
        return self::integer('refresh-tokens.ttl', config('refresh-tokens.ttl'), 2_592_000, min: 1);
    }

    /**
     * The absolute session cap in seconds (`refresh-tokens.absolute_ttl`); 0 disables it.
     */
    public static function absoluteTtl(): int
    {
        return self::integer('refresh-tokens.absolute_ttl', config('refresh-tokens.absolute_ttl'), 7_776_000, min: 0);
    }

    /**
     * The configured `refresh-tokens.token_length`, unbounded here — {@see TokenHasher}
     * applies the bounds with its own messages.
     */
    public static function tokenLength(): int
    {
        return self::integer('refresh-tokens.token_length', config('refresh-tokens.token_length'), 64);
    }

    /**
     * A strict integer: `$default` when `$value` is not set (null or blank); otherwise
     * an int or a canonical integer string within the bounds, or a throw naming `$key`.
     *
     * @throws InvalidTokenConfigurationException
     */
    public static function integer(string $key, mixed $value, int $default, ?int $min = null, ?int $max = null): int
    {
        return Config::for([$key => $value], InvalidTokenConfigurationException::class)->integer($key, $default, $min, $max);
    }

    /**
     * A required string: `$default` when `$value` is not set (null or blank); a
     * non-string value throws instead of silently reading as the default.
     *
     * @throws InvalidTokenConfigurationException
     */
    public static function string(string $key, mixed $value, string $default): string
    {
        if (self::notSet($value)) {
            return $default;
        }

        if (! is_string($value)) {
            throw InvalidTokenConfigurationException::notAString($key, $value);
        }

        return $value;
    }

    /**
     * Absent, null or blank (`''` or whitespace): the key is not set, so its default
     * applies — a host's `KEY=` means the same as leaving the key out.
     */
    public static function notSet(mixed $value): bool
    {
        return $value === null || (is_string($value) && trim($value) === '');
    }
}
