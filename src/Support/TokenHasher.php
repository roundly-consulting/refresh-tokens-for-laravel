<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Random\Token;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use SensitiveParameter;

/**
 * The package's boundary onto crypto-for-laravel: it reads refresh-tokens' own
 * config and hands the resulting algorithm, length, and pepper to the shared
 * primitives ({@see Digest}, {@see Token}), so the at-rest representation still
 * lives in exactly one place.
 *
 * The digest is unchanged and must stay so: `token_hash` holds the hash of every
 * live token in every host's database, and the plaintext is not recoverable — a
 * different digest would silently log every user out. SHA-256 is deliberate: the
 * plaintext already carries ~380 bits of entropy, so a fast, indexed-equality-
 * friendly digest is correct. Set `refresh-tokens.hash.key` to switch to an HMAC
 * pepper (defence-in-depth).
 */
final class TokenHasher
{
    /**
     * The shortest plaintext the package will mint. Below this a token is
     * brute-forceable; a misconfiguration must fail loudly, not silently.
     */
    public const int MINIMUM_TOKEN_LENGTH = Token::MINIMUM_LENGTH;

    /**
     * The longest plaintext the package will mint — crypto's own ceiling, so a
     * length wired to untrusted input cannot turn into a DoS.
     */
    public const int MAXIMUM_TOKEN_LENGTH = Token::MAXIMUM_LENGTH;

    /**
     * The at-rest hashing allowlist. Restricting `hash.algo` to these stops an env
     * typo (e.g. `md5`, `crc32b`, or crypto's legacy-interop `sha1`) from silently
     * weakening the token store; every member is a fast, fixed-width SHA-2 digest
     * that fits the `token_hash` column.
     *
     * @var list<HashAlgorithm>
     */
    private const array ALLOWED_ALGORITHMS = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ];

    /**
     * Generate a fresh high-entropy plaintext secret.
     *
     * @throws InvalidTokenConfigurationException on a length outside the bounds
     */
    public function generate(): string
    {
        // The length is bounds-checked against crypto's own constants first, so
        // Token::urlSafe() can never raise a CryptoException here.
        return Token::urlSafe($this->length());
    }

    /**
     * Hash a plaintext for at-rest storage / lookup. Deterministic: the same
     * plaintext always yields the same digest, enabling a unique-index lookup.
     *
     * @throws InvalidTokenConfigurationException on an algorithm outside the allowlist
     */
    public function hash(#[SensitiveParameter] string $plain): string
    {
        return (new Digest($this->algo()))->withPepper($plain, $this->key());
    }

    /**
     * @throws InvalidTokenConfigurationException when configured outside the bounds
     */
    private function length(): int
    {
        $length = config('refresh-tokens.token_length', 64);
        $length = is_int($length) ? $length : 64;

        if ($length < self::MINIMUM_TOKEN_LENGTH) {
            throw InvalidTokenConfigurationException::tokenLengthTooShort($length, self::MINIMUM_TOKEN_LENGTH);
        }

        if ($length > self::MAXIMUM_TOKEN_LENGTH) {
            throw InvalidTokenConfigurationException::tokenLengthTooLong($length, self::MAXIMUM_TOKEN_LENGTH);
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

        $resolved = HashAlgorithm::tryFrom($algo);

        // Crypto's enum also carries SHA-1 for legacy interop; the token store must
        // never select it, so membership of the SHA-2 allowlist is checked too.
        return $resolved !== null && in_array($resolved, self::ALLOWED_ALGORITHMS, true)
            ? $resolved
            : throw InvalidTokenConfigurationException::unsupportedAlgorithm($algo, self::allowedAlgorithms());
    }

    private function key(): ?string
    {
        $key = config('refresh-tokens.hash.key');

        // A missing, empty, or whitespace-only key means "no pepper" — fall back to a
        // plain hash. A real pepper is used verbatim (never trimmed).
        return is_string($key) && trim($key) !== '' ? $key : null;
    }

    /**
     * @return list<string>
     */
    private static function allowedAlgorithms(): array
    {
        return array_map(
            static fn (HashAlgorithm $case): string => $case->value,
            self::ALLOWED_ALGORITHMS,
        );
    }
}
