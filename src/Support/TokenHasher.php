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
        $length = Settings::tokenLength();

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
        // Absent reads as sha256; a blank or non-string value is refused like any other
        // name outside the allowlist, never quietly replaced by the default.
        $algo = config('refresh-tokens.hash.algo') ?? 'sha256';

        if (! is_string($algo)) {
            throw InvalidTokenConfigurationException::unsupportedAlgorithm(get_debug_type($algo), self::allowedAlgorithms());
        }

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

        // A missing, empty, or whitespace-only key means "no pepper" (`REFRESH_TOKENS_HASH_KEY=`
        // in a .env): a plain hash. A pepper that is not a string at all throws rather than
        // silently dropping the pepper. A real pepper is used verbatim (never trimmed).
        if ($key !== null && ! is_string($key)) {
            throw InvalidTokenConfigurationException::notAString('refresh-tokens.hash.key', $key);
        }

        return $key !== null && trim($key) !== '' ? $key : null;
    }

    /**
     * The at-rest hashing allowlist, as raw algorithm names. Public so the
     * service provider's `about` section can report the configured digest
     * without duplicating the allowlist (or resolving it, which throws).
     *
     * @return list<string>
     */
    public static function allowedAlgorithms(): array
    {
        return array_map(
            static fn (HashAlgorithm $case): string => $case->value,
            self::ALLOWED_ALGORITHMS,
        );
    }
}
