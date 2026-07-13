<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Support\TokenHasher;

/*
 * AT-REST DIGEST PARITY — the safety net for this package.
 *
 * `refresh_tokens.token_hash` stores the digest of every live refresh token in
 * every host's database, and the plaintext is NOT recoverable. If the digest of a
 * given plaintext ever changes, every deployed token silently stops verifying and
 * every user is logged out — no migration can repair it.
 *
 * The expected values below were computed from the pre-crypto implementation
 * (`hash($algo, $plain)` / `hash_hmac($algo, $plain, $key)`, PHP's default
 * lower-case hex output) BEFORE the retrofit, and are pinned here verbatim. Any
 * change to the algorithm, the encoding (hex vs raw vs base64), or the pepper
 * handling breaks this test. Do not regenerate these values — fix the code.
 */

/** The fixed plaintext the vectors below were generated from. */
const PARITY_PLAINTEXT = 'rt_fixed_plaintext_for_at_rest_parity_0123456789';

/**
 * A pepper with leading/trailing whitespace and a non-breaking space, pinning the
 * "used verbatim, never trimmed" contract: the HMAC key is the raw config string.
 */
const PARITY_PEPPER = "pepper-\u{00A0} verbatim  ";

dataset('unpeppered digests', [
    ['sha256', 'e36e7ca16c14b0a28ea420fb3725f6ed2b65c7594022d60d98da1bebc002dce2'],
    ['sha384', '505d869dd05686336f969fceb1ff408fe8aa6ab29797acff3a5b837fa7f16b9e24854f554c27112f18a1c0fa02c6623c'],
    ['sha512', 'ef9dff940402eb0571f4677efa1076148aea63785c62a263224bd4661445347d98ef813587741bc63d2137bdca43e90170aceee0a3ff4c40062dfee708b4d027'],
]);

dataset('peppered digests', [
    ['sha256', 'cd9e62b239037d9bebf7abc251e0a88aec59a1a5ceed564d10bfc76b08aa6b6f'],
    ['sha384', '7006707458fee1a4f207aeed6cebcb3b7fcdf05542ce204562aea75a05620d4f28d0e16029344df2810256af42bab5c1'],
    ['sha512', 'a80e7a14eea116cc0117551af2f6881a507e0f4b1ee1cc420464dee1cd35d32206e68e78ccba24305dd5e6739ab3076994aa625df672553f7e771a91984b6419'],
]);

it('reproduces the pinned unpeppered digest for every supported algorithm', function (string $algo, string $expected): void {
    config()->set('refresh-tokens.hash.algo', $algo);
    config()->set('refresh-tokens.hash.key', null);

    expect((new TokenHasher)->hash(PARITY_PLAINTEXT))->toBe($expected);
})->with('unpeppered digests');

it('reproduces the pinned peppered digest for every supported algorithm', function (string $algo, string $expected): void {
    config()->set('refresh-tokens.hash.algo', $algo);
    config()->set('refresh-tokens.hash.key', PARITY_PEPPER);

    expect((new TokenHasher)->hash(PARITY_PLAINTEXT))->toBe($expected);
})->with('peppered digests');

it('uses the pepper verbatim — a trimmed pepper is a different digest', function (): void {
    config()->set('refresh-tokens.hash.key', PARITY_PEPPER);
    $verbatim = (new TokenHasher)->hash(PARITY_PLAINTEXT);

    config()->set('refresh-tokens.hash.key', trim(PARITY_PEPPER));
    $trimmed = (new TokenHasher)->hash(PARITY_PLAINTEXT);

    expect($verbatim)->not->toBe($trimmed)
        ->and($verbatim)->toBe(hash_hmac('sha256', PARITY_PLAINTEXT, PARITY_PEPPER));
});

it('stores a lower-case hex digest of the algorithm width, never raw bytes', function (string $algo, int $width): void {
    config()->set('refresh-tokens.hash.algo', $algo);

    $digest = (new TokenHasher)->hash(PARITY_PLAINTEXT);

    expect($digest)->toHaveLength($width)
        ->and(ctype_xdigit($digest))->toBeTrue()
        ->and($digest)->toBe(strtolower($digest));
})->with([
    ['sha256', 64],
    ['sha384', 96],
    ['sha512', 128],
]);
