<p align="center">
  <a href="https://roundly-consulting.com/open-source">
    <img src="art/hero.png" alt="Refresh Tokens For Laravel — Roundly open source" width="100%">
  </a>
</p>

# Refresh Tokens for Laravel

Opaque, rotating **refresh tokens** and **device sessions** for Laravel — SHA-256 at rest,
atomic single-query anti-double-spend rotation, always-on family revocation on reuse
detection, and first-class session management. **Zero third-party runtime dependencies.**

This package owns the full lifecycle of refresh tokens and sessions. It deliberately stays
out of concerns the host already owns: JWT minting/verification and jti denylisting, user-agent
parsing, IP geolocation, HTTP routes/controllers, and cookie transport. Those plug in through a
small contract and DTO inputs.

## Requirements

- PHP 8.4+
- Laravel 12 or 13

## Installation

```bash
composer require roundly-consulting/refresh-tokens-for-laravel
```

Publish and run the migration:

```bash
php artisan vendor:publish --tag="refresh-tokens-migrations"
php artisan migrate
```

Optionally publish the config file:

```bash
php artisan vendor:publish --tag="refresh-tokens-config"
```

Add the trait to your user model to expose its tokens and sessions:

```php
use RoundlyConsulting\RefreshTokens\Traits\HasRefreshTokens;

final class User extends Authenticatable
{
    use HasRefreshTokens;
}
```

## Configuration

The published `config/refresh-tokens.php`:

| Key | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `table` | string | `refresh_tokens` | `REFRESH_TOKENS_TABLE` | Table name. |
| `model` | class-string | `RefreshToken::class` | — | Model class; swap for a host subclass. |
| `user_model` | class-string | `App\Models\User` | `REFRESH_TOKENS_USER_MODEL` | Owner model for the relation. |
| `foreign_key` | string | `user_id` | `REFRESH_TOKENS_FOREIGN_KEY` | Owner foreign key. |
| `ttl` | int (seconds) | `2592000` (30 days) | `REFRESH_TOKENS_TTL` | Token lifetime. |
| `token_length` | int | `64` | `REFRESH_TOKENS_LENGTH` | Plaintext length (~380 bits at 64). |
| `hash.algo` | string | `sha256` | `REFRESH_TOKENS_HASH_ALGO` | At-rest hash algorithm. |
| `hash.key` | ?string | `null` | `REFRESH_TOKENS_HASH_KEY` | Optional HMAC pepper; null = plain hash. |
| `rotation.grace` | int (seconds) | `0` | `REFRESH_TOKENS_ROTATION_GRACE` | Benign single-flight window before a re-presented token counts as reuse. `0` = strict. |
| `prune.after` | int (days) | `30` | `REFRESH_TOKENS_PRUNE_AFTER` | Retention past revoke/expiry before pruning. |

The package works with **zero** configuration — every key has a sensible env-backed default.

### Why SHA-256 (not bcrypt/argon)?

A refresh token is a 64-char CSPRNG secret with ~380 bits of entropy. A slow password hash adds
nothing against a secret that can't be brute-forced and would break the indexed unique-equality
lookup rotation relies on. Set `hash.key` to layer an HMAC pepper on top for defence-in-depth if
a database dump leaks.

### Pepper (defence-in-depth)

By default tokens are stored as a plain SHA-256 digest. Set `hash.key` (env
`REFRESH_TOKENS_HASH_KEY`) to a high-entropy secret and the at-rest digest becomes
`hash_hmac('sha256', $plain, $key)` instead — a single deterministic value under the same unique
index, so the lookup and the atomic-claim mutex are unchanged. What it buys you: an attacker who
exfiltrates the database table but **not** the application secret cannot verify or brute-force any
token, even a weak one.

```dotenv
REFRESH_TOKENS_HASH_KEY=base64:your-high-entropy-secret
```

Keep the pepper outside the database (env / secrets manager) and treat it like `APP_KEY`. A
missing or whitespace-only value means "no pepper" (plain SHA-256).

**Caveat — changing `hash.key` invalidates existing tokens.** The pepper participates in the
digest, so setting, rotating, or clearing it makes every previously stored digest stop matching;
holders must re-authenticate. This is expected. The package does **not** ship online pepper
rotation (accepting old and new peppers at once) — pick a pepper up front, or plan a re-login
window when you change it.

## Usage

All examples use the `RefreshToken` facade
(`RoundlyConsulting\RefreshTokens\Facades\RefreshToken`).

### Issue

The host mints its access token **first**, then issues the refresh token linked to it. The
plaintext is returned **once** — never stored:

```php
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;

$new = RefreshToken::issue($user, new IssueContext(
    ipAddress: $request->ip(),
    userAgent: $request->userAgent(),
    accessReference: $access->jti, // opaque link to the host's access token
));

$plainText = $new->plainText;      // return to the client ONCE
```

Or the fluent builder:

```php
$new = RefreshToken::for($user)
    ->fromRequest($request)        // fills ip + user agent
    ->linkedTo($access->jti)
    ->issue();
```

### Rotate

`redeem()` atomically claims and rotates a token. Of N concurrent redemptions of the same
token, exactly one wins; every failure mode collapses to `null`:

```php
$result = RefreshToken::redeem($plainFromClient); // ?RedemptionResult
if ($result === null) {
    // unknown / expired / revoked / race-lost / reuse — host maps to its own error
    throw ValidationException::withMessages([...]);
}

$user = $result->user;
$familyId = $result->familyId;
```

`rotate()` does redeem + issue a same-family replacement in one call (mint the new access token
first, pass its reference):

```php
$rotation = RefreshToken::rotate($plainFromClient, linkedTo: $newAccess->jti);
// ?RotationResult { user, newRefreshToken (NewRefreshToken), redeemedFamilyId }
```

### Reuse detection

Presenting an already-rotated token is a theft signal. The **entire token family** is revoked,
the host callback is invoked for every live member's access token, and a
`RefreshTokenReuseDetected` event fires — all automatically, no config switch. Tune
`rotation.grace` if your frontend legitimately re-presents a token within a short single-flight
window.

### Revoke / logout

```php
RefreshToken::revoke($plainFromClient);  // logout with token in hand (idempotent)
RefreshToken::revokeAllFor($user);       // global logout — returns count revoked
```

### Sessions

A session is an active refresh-token row. The `current` flag is derived by the host by
comparing the request's access reference to each row's `access_reference`.

```php
$sessions = RefreshToken::listFor($user);                 // active, newest first
RefreshToken::revokeOthers($user, $currentAccess->jti);   // keep current, revoke the rest
RefreshToken::revokeAll($user);                           // revoke every session

// On the user model via the trait:
$user->refreshTokens();  // HasMany, all tokens
$user->sessions();       // HasMany, active tokens only
```

The trait also adds `$user->…()` verbs that read as the user acting on itself:

```php
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;

$new = $user->issueRefreshToken(new IssueContext(accessReference: $access->jti));
$user->revokeAllSessions();                 // = RefreshToken::revokeAllFor($user); returns count
$user->revokeOtherSessions($currentAccess->jti); // keep current, revoke the rest; returns count
```

### Log out everywhere on a password change

The canonical reaction to a credential change is to revoke every session. Wire it from your
change-password flow, or from a model observer when the password attribute is dirty — the package
ships the verb but never hooks your User model for you:

```php
// In a change-password action:
$user->update(['password' => Hash::make($newPassword)]);
$user->revokeAllSessions();

// …or via a saved observer:
User::saved(function (User $user): void {
    if ($user->wasChanged('password')) {
        $user->revokeAllSessions();
    }
});
```

### Binding the access-token revoker

By default the package ships a no-op `AccessTokenRevoker`, so it works standalone. Bind your own
adapter to deny access tokens (e.g. a JWT jti denylist) when a session or family is revoked:

```php
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;

$this->app->singleton(AccessTokenRevoker::class, DenylistAccessTokenRevoker::class);

final class DenylistAccessTokenRevoker implements AccessTokenRevoker
{
    public function revoke(#[\SensitiveParameter] string $accessReference): void
    {
        // e.g. add $accessReference to your jwt jti denylist until its TTL expires
    }
}
```

### Enriching a session (device + geo)

The package never parses a user agent or geolocates an IP — the host supplies already-parsed
data, typically from an async job hooked to the `RefreshTokenIssued` event:

```php
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\Enums\DeviceType;

// Pass the RefreshToken model you already hold, or its id:
RefreshToken::enrich($new->token,
    new DeviceData(browser: 'Firefox', os: 'Linux', deviceType: DeviceType::Desktop, isBot: false),
    new LocationData(country: 'Slovakia', city: 'Bratislava', countryCode: 'SK', ipAddress: '203.0.113.9'),
);
```

`enrich()` accepts the `RefreshToken` model, an int, or a string key. **Write semantics:** it only
ever touches device/geo columns — never the auth columns. The six device columns are **always
overwritten** (an absent `DeviceData` field nulls its column), while the location columns are
written **only when a `LocationData` is supplied** — so a later device-only enrich never clobbers
previously stored geo.

### Events

Hook these on the host side; they carry ids/scalars only (never the model or plaintext):

- `RefreshTokenIssued(int|string $tokenId)` — trigger async device/geo enrichment.
- `RefreshTokenRedeemed(int|string $tokenId, string $familyId, int|string $userId)` — a token was
  legitimately spent (rotated); hook it to audit rotations or meter session churn.
- `SessionRevoked(int|string $tokenId, ?string $accessReference)`.
- `RefreshTokenReuseDetected(string $familyId, int|string $userId, int $revokedCount)` — theft
  signal for alerting; `revokedCount` reports how many live family members were revoked in
  response.

`rotate()` fires one `RefreshTokenRedeemed` (for the spent token) **and** one `RefreshTokenIssued`
(for the replacement).

### Pruning

Dead rows (revoked/expired past `prune.after`) are force-deleted by the command or
`model:prune`. The package does **not** self-schedule — the host schedules it:

```php
// bootstrap/app.php or a scheduler
$schedule->command('refresh-tokens:prune')->daily();
```

```bash
php artisan refresh-tokens:prune            # uses config('refresh-tokens.prune.after')
php artisan refresh-tokens:prune --days=7   # override retention
```

## Security

- **SHA-256 at rest** under a unique index; the plaintext is returned once and never persisted.
- **Single-query anti-double-spend** rotation (`WHERE revoked_at IS NULL` compare-and-swap) — no
  transaction, no row lock; works identically on PostgreSQL and SQLite.
- **Always-on family revocation** on reuse detection.
- `#[SensitiveParameter]` on every plaintext parameter; plaintext and hashes are never logged.

Intentionally host-owned (not this package): JWT minting/verification, jti denylisting,
user-agent parsing, IP geolocation, HTTP routes/controllers, throttling, and cookie transport.

## Testing

Assert your access-token revocation with the shipped `FakeAccessTokenRevoker` — bind it in place
of your real revoker and assert exactly which access references the package asked to deny, no
hand-rolled spy required:

```php
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;

$fake = new FakeAccessTokenRevoker();
$this->app->instance(AccessTokenRevoker::class, $fake);

// … exercise reuse detection / session revocation …

$fake->assertRevoked($jti);
$fake->assertNotRevoked($otherJti);
$fake->assertRevokedCount(2);
$fake->assertNothingRevoked();   // when nothing should have been denied
```

Its assertions throw a package exception (not a PHPUnit assertion), so it works under any runner.

Run the package's own suite with:

```bash
composer test
composer test-coverage
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

The MIT License (MIT). Copyright (c) roundly-consulting. See [LICENSE.md](LICENSE.md).
