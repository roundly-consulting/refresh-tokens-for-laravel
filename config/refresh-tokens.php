<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

return [
    // Storage
    'table' => env('REFRESH_TOKENS_TABLE', 'refresh_tokens'),
    'model' => RefreshToken::class,
    'user_model' => env('REFRESH_TOKENS_USER_MODEL', 'App\\Models\\User'),
    'foreign_key' => env('REFRESH_TOKENS_FOREIGN_KEY', 'user_id'),

    // Token lifetime & shape
    'ttl' => (int) env('REFRESH_TOKENS_TTL', 2_592_000), // seconds; 30 days
    'token_length' => (int) env('REFRESH_TOKENS_LENGTH', 64), // Str::random chars (~380 bits)

    // Hashing at rest. SHA-256 by default: the secret already carries ~380 bits of entropy,
    // so a fast, indexed-equality-friendly hash is correct — a slow password hash would add
    // nothing and break the unique-index lookup. Set `hash.key` to opt into an HMAC pepper
    // (defence-in-depth if a DB dump leaks); left unset (or whitespace-only) it is plain SHA-256.
    //
    // CAVEAT: `hash.key` participates in the at-rest digest, so changing it (setting, rotating,
    // or clearing) invalidates every existing token — their stored digest no longer matches, so
    // holders must re-authenticate. Treat it as a high-entropy secret kept outside the database.
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
