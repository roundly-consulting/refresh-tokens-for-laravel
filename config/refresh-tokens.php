<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

return [
    // Storage
    'table' => env('REFRESH_TOKENS_TABLE', 'refresh_tokens'),
    'model' => RefreshToken::class,
    'user_model' => env('REFRESH_TOKENS_USER_MODEL', 'App\\Models\\User'),
    'foreign_key' => env('REFRESH_TOKENS_FOREIGN_KEY', 'user_id'),

    // Primary-key type of the user model, driving the foreign-key column: `id`
    // (auto-incrementing bigint, default), `uuid`, or `ulid`. Set this before the
    // first migration to match a UUID/ULID-keyed user model.
    'user_key_type' => env('REFRESH_TOKENS_USER_KEY_TYPE', 'id'),

    // Token lifetime & shape
    'ttl' => (int) env('REFRESH_TOKENS_TTL', 2_592_000), // seconds; 30 days (sliding)

    // Absolute session lifetime cap. Every rotation clamps the replacement's expiry
    // to the family root's creation time plus this many seconds, so a continuously
    // rotated (or stolen-but-active) session cannot live forever. 0 disables the cap.
    'absolute_ttl' => (int) env('REFRESH_TOKENS_ABSOLUTE_TTL', 7_776_000), // seconds; 90 days

    'token_length' => (int) env('REFRESH_TOKENS_LENGTH', 64), // base64url chars (~384 bits); min 32, max 4096

    // Hashing at rest. SHA-256 by default: the secret already carries ~380 bits of entropy,
    // so a fast, indexed-equality-friendly hash is correct — a slow password hash would add
    // nothing and break the unique-index lookup. Set `hash.key` to opt into an HMAC pepper
    // (defence-in-depth if a DB dump leaks); left unset (or whitespace-only) it is plain SHA-256.
    //
    // CAVEAT: `hash.key` participates in the at-rest digest, so changing it (setting, rotating,
    // or clearing) invalidates every existing token — their stored digest no longer matches, so
    // holders must re-authenticate. Treat it as a high-entropy secret kept outside the database.
    // `algo` is restricted to the SHA-2 allowlist (sha256 | sha384 | sha512); any other
    // value throws InvalidTokenConfigurationException rather than silently weakening the
    // digest. All three fit the 128-char token_hash column.
    'hash' => [
        'algo' => env('REFRESH_TOKENS_HASH_ALGO', 'sha256'),
        'key' => env('REFRESH_TOKENS_HASH_KEY'), // optional HMAC pepper; null = plain hash
    ],

    // Rotation / anti-replay
    'rotation' => [
        // Seconds a losing concurrent redemption stays benign (single-flight retry) before it
        // counts as reuse. 0 = strict (any post-rotation presentation is treated as reuse).
        'grace' => (int) env('REFRESH_TOKENS_ROTATION_GRACE', 0),
    ],

    // Expiry sweeping (the host schedules the command / model:prune)
    'prune' => [
        'after' => (int) env('REFRESH_TOKENS_PRUNE_AFTER', 30), // days past revoke/expiry
    ],
];
