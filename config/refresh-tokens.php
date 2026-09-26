<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

return [
    // Storage
    'table' => env('REFRESH_TOKENS_TABLE', 'refresh_tokens'),
    'model' => RefreshToken::class,

    // Cast for the `device_type` column. Defaults to the packaged `DeviceType` enum
    // (desktop/mobile/tablet/bot/unknown) — the recommended, typed shape where the host
    // maps its parsed device class to those cases. A host whose device vocabulary is
    // richer/free-form (e.g. a dedicated user-agent service emitting many device names)
    // may set this to `'string'` to store the raw value verbatim. Any Eloquent cast
    // string is accepted; an empty value falls back to the enum.
    'device_type_cast' => DeviceType::class,

    // Tokens hang off a polymorphic owner (`owner_type` + `owner_id`), so any
    // Authenticatable Eloquent model — users, clients, admins — can hold sessions in
    // the one table. This is the primary-key type shared by EVERY owner model, driving
    // the `owner_id` column: `bigint` (auto-incrementing, the default; `id` is accepted
    // as an alias), `uuid`, or `ulid`. Set it before the first migration. Owner models
    // with different key types cannot share the table. An unrecognized value falls back
    // to `bigint` — a typo must never silently reshape (or break) the schema.
    'key_type' => env('REFRESH_TOKENS_KEY_TYPE', 'bigint'),

    // Token lifetime & shape
    // Both lifetimes are defaults: a single issue may override them through
    // IssueContext `ttl` / `absoluteTtl` (e.g. a per-guard lifetime).
    'ttl' => (int) env('REFRESH_TOKENS_TTL', 2_592_000), // seconds; 30 days (sliding)

    // Absolute session lifetime cap. When a family is rooted its hard end
    // (`absolute_expires_at` = start + this many seconds) is stored on the row and
    // inherited verbatim by every rotation, which clamps each replacement's expiry to
    // it — a continuously rotated (or stolen-but-active) session cannot live forever.
    // 0 disables the cap.
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
