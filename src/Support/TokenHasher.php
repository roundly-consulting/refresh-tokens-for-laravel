<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\Enums\HashAlgorithm;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use SensitiveParameter;

/**
 * Centralises token generation and hashing so the at-rest representation lives in
 * exactly one place. SHA-256 is deliberate: the plaintext already carries ~380
 * bits of entropy, so a fast, indexed-equality-friendly digest is correct. Set
 * `refresh-tokens.hash.key` to switch to an HMAC pepper (defence-in-depth).
 */
final class TokenHasher
{
    /**
     * The shortest plaintext (Str::random chars) the package will mint. Below this
     * a token is brute-forceable; a misconfiguration must fail loudly, not silently.
     */
    public const int MINIMUM_TOKEN_LENGTH = 32;

    /**
     * Generate a fresh high-entropy plaintext secret.
     */
    public function generate(): string
    {
        return Str::random($this->length());
    }

    /**
     * Hash a plaintext for at-rest storage / lookup. Deterministic: the same
     * plaintext always yields the same digest, enabling a unique-index lookup.
     */
    public function hash(#[SensitiveParameter] string $plain): string
    {
        $algo = $this->algo()->value;
        $key = $this->key();

        return $key === null
            ? hash($algo, $plain)
            : hash_hmac($algo, $plain, $key);
    }

    /**
     * @throws InvalidTokenConfigurationException when configured below the minimum
     */
    private function length(): int
    {
        $length = config('refresh-tokens.token_length', 64);
        $length = is_int($length) ? $length : 64;

        if ($length < self::MINIMUM_TOKEN_LENGTH) {
            throw InvalidTokenConfigurationException::tokenLengthTooShort($length, self::MINIMUM_TOKEN_LENGTH);
        }

        return $length;
    }

    /**
     * @throws InvalidTokenConfigurationException on an algorithm outside the allowlist
     */
    private function algo(): HashAlgorithm
    {
        $algo = config('refresh-tokens.hash.algo', 'sha256');
        $algo = is_string($algo) && $algo !== '' ? $algo : 'sha256';

        return HashAlgorithm::tryFrom($algo) ?? throw InvalidTokenConfigurationException::unsupportedAlgorithm(
            $algo,
            array_map(static fn (HashAlgorithm $case): string => $case->value, HashAlgorithm::cases()),
        );
    }

    private function key(): ?string
    {
        $key = config('refresh-tokens.hash.key');

        // A missing, empty, or whitespace-only key means "no pepper" — fall back to a
        // plain hash. A real pepper is used verbatim (never trimmed).
        return is_string($key) && trim($key) !== '' ? $key : null;
    }
}
