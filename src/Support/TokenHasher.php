<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Support\Str;
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
        $algo = $this->algo();
        $key = $this->key();

        return $key === null
            ? hash($algo, $plain)
            : hash_hmac($algo, $plain, $key);
    }

    private function length(): int
    {
        $length = config('refresh-tokens.token_length', 64);

        return is_int($length) && $length > 0 ? $length : 64;
    }

    private function algo(): string
    {
        $algo = config('refresh-tokens.hash.algo', 'sha256');

        return is_string($algo) && $algo !== '' ? $algo : 'sha256';
    }

    private function key(): ?string
    {
        $key = config('refresh-tokens.hash.key');

        // A missing, empty, or whitespace-only key means "no pepper" — fall back to a
        // plain hash. A real pepper is used verbatim (never trimmed).
        return is_string($key) && trim($key) !== '' ? $key : null;
    }
}
