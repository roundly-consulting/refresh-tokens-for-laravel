<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/refresh-tokens-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=refresh-tokens-for-laravel">
    <img src="art/hero.png" alt="Refresh Tokens for Laravel — Roundly open source" width="100%">
  </a>
</p>
<!-- roundly-hero:end -->

<!-- roundly-badges:start -->
<p align="center">
  <a href="https://packagist.org/packages/roundly-consulting/refresh-tokens-for-laravel"><img src="https://img.shields.io/packagist/v/roundly-consulting/refresh-tokens-for-laravel?style=flat-square&label=release" alt="Latest release"></a>
  <a href="https://github.com/roundly-consulting/refresh-tokens-for-laravel/actions/workflows/run-tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/refresh-tokens-for-laravel/run-tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://github.com/roundly-consulting/refresh-tokens-for-laravel/actions/workflows/fix-php-code-style-issues.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/refresh-tokens-for-laravel/fix-php-code-style-issues.yml?branch=main&style=flat-square&label=code%20style" alt="Code style"></a>
  <a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/donate-support%20our%20open%20source-F24E29?style=flat-square&logo=stripe&logoColor=white" alt="Donate"></a>
  <a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/patreon-become%20a%20patron-F96854?style=flat-square&logo=patreon&logoColor=white" alt="Patreon"></a>
  <a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=refresh-tokens-for-laravel#crypto"><img src="https://img.shields.io/badge/crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=flat-square&logo=bitcoin&logoColor=white" alt="Crypto"></a>
</p>
<!-- roundly-badges:end -->

# Refresh Tokens for Laravel

Opaque, rotating **refresh tokens** and **device sessions** for Laravel — SHA-256 at rest,
atomic single-query anti-double-spend rotation, always-on family revocation on reuse
detection, and first-class session management. Tokens hang off a **polymorphic owner**, so users,
API clients, admins — any `Authenticatable` model — share one table without their ids colliding.
**Zero third-party runtime dependencies.**

This package owns the full lifecycle of refresh tokens and sessions. It deliberately stays
out of concerns the host already owns: JWT minting/verification and jti denylisting, user-agent
parsing, IP geolocation, HTTP routes/controllers, and cookie transport. Those plug in through a
small contract and DTO inputs.

## Requirements

- PHP 8.4+
- Laravel 12 or 13

## Integrates with

- **[crypto-for-laravel](https://github.com/roundly-consulting/crypto-for-laravel)** — the at-rest
  digest (`Crypto\Hash\Digest`, plain or HMAC-peppered) and the CSPRNG plaintext
  (`Crypto\Random\Token`) come from the shared, audited crypto package, so the token store and the
  entropy floor are maintained in one place instead of re-implemented here. Installed automatically;
  nothing to configure — this package still owns `config/refresh-tokens.php` and hands the
  algorithm, length, and pepper to crypto at the boundary.
- **[enums-for-laravel](https://github.com/roundly-consulting/enums-for-laravel)** — labels and
  select options on `RevocationReason` and `DeviceType`.
- **[package-toolkit-for-laravel](https://github.com/roundly-consulting/package-toolkit-for-laravel)**
  — the service provider, the `key_type` → column mapping (`KeyType` + the `morphKey()` schema macro),
  the model resolver behind `refresh-tokens.model`, and the `php artisan about` section. Installed
  automatically; nothing to configure.

## Installation

```bash
composer require roundly-consulting/refresh-tokens-for-laravel
```

**Migrations are publish-only** — the package does not load them, so publish first, then migrate.
If your owner models are UUID/ULID-keyed, publish the config and set `key_type` **before** you
migrate (the `owner_id` column is baked into the schema):

```bash
php artisan vendor:publish --tag="refresh-tokens-migrations"
php artisan migrate
```

Optionally publish the config file:

```bash
php artisan vendor:publish --tag="refresh-tokens-config"
```

Add the trait to every model that holds sessions — any `Authenticatable` Eloquent model:

```php
use RoundlyConsulting\RefreshTokens\Traits\HasRefreshTokens;

final class User extends Authenticatable
{
    use HasRefreshTokens;
}

final class Client extends Authenticatable   // a second, isolated account type
{
    use HasRefreshTokens;
}
```

### Adopting an existing tokens table

A host that already has a tokens table can reproduce the package shape from its own migration:
`RefreshTokenBlueprint::columns($table, $keyType)` emits the full table, and
`RefreshTokenBlueprint::addSessionColumns($table)` adds only the session columns
(`family_started_at`, `absolute_expires_at`, `meta` — all nullable, so they fit a populated table).
Backfill `owner_type` / `family_started_at` / `absolute_expires_at` in the same migration.

## Configuration

The published `config/refresh-tokens.php`:

| Key | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `table` | string | `refresh_tokens` | `REFRESH_TOKENS_TABLE` | Table name. |
| `model` | class-string | `RefreshToken::class` | — | Model class; swap for a host subclass. |
| `device_type_cast` | string | `DeviceType::class` | — | Eloquent cast for the `device_type` column. The packaged `DeviceType` enum (`desktop`/`mobile`/`tablet`/`bot`/`unknown`) by default; set `'string'` (or any Eloquent cast) to store a free-form device name verbatim. An empty value falls back to the enum. |
| `key_type` | string | `bigint` | `REFRESH_TOKENS_KEY_TYPE` | Primary-key type shared by every owner model, driving the `owner_id` column: `bigint`, `uuid`, or `ulid`. An unrecognized value falls back to `bigint`. |
| `ttl` | int (seconds) | `2592000` (30 days) | `REFRESH_TOKENS_TTL` | Default sliding token lifetime per issue/rotation (per-issue override: `IssueContext::$ttl`). |
| `absolute_ttl` | int (seconds) | `7776000` (90 days) | `REFRESH_TOKENS_ABSOLUTE_TTL` | Default absolute cap on a session, stored when the family is rooted (per-issue override: `IssueContext::$absoluteTtl`). `0` disables. |
| `token_length` | int | `64` | `REFRESH_TOKENS_LENGTH` | Plaintext length in base64url chars (~384 bits at 64). Minimum `32`, maximum `4096` — outside it throws. |
| `hash.algo` | string | `sha256` | `REFRESH_TOKENS_HASH_ALGO` | At-rest hash algorithm; allowlisted to `sha256`, `sha384`, `sha512`. |
| `hash.key` | ?string | `null` | `REFRESH_TOKENS_HASH_KEY` | Optional HMAC pepper; null = plain hash. |
| `rotation.grace` | int (seconds) | `0` | `REFRESH_TOKENS_ROTATION_GRACE` | Benign single-flight window before a re-presented token counts as reuse. `0` = strict. |
| `prune.after` | int (days) | `30` | `REFRESH_TOKENS_PRUNE_AFTER` | Retention past revoke/expiry before pruning. Floored at `1` day. |

The package works with **zero** configuration — every key has a sensible env-backed default.

Inspect the live configuration with:

```bash
php artisan about --only=refresh-tokens
```

The section is **secret-safe**: the pepper reports as `SET`/`MISSING` and never as a value, and a
renamed table or a bound revoker reports as `CUSTOM`/`BOUND` — nothing a support screenshot could
leak.

### Validated configuration (fail loud, not silent)

Two security-relevant keys are validated rather than silently coerced, so an env typo can't
degrade the token store:

- **`hash.algo`** is restricted to the SHA-2 allowlist (`sha256`, `sha384`, `sha512`). Any other
  value (`md5`, `crc32b`, …) throws `InvalidTokenConfigurationException`. All three allowed digests
  fit the `token_hash` column (widened to 128 chars for `sha512`).
- **`token_length`** enforces a floor of **32** characters; a shorter value throws
  `InvalidTokenConfigurationException` instead of minting a brute-forceable token.

### Owners (polymorphic) and their key type

Every token row carries `owner_type` (the owner's morph class — respects your
`Relation::morphMap()`) and `owner_id`, with a composite index. Owner-scoped queries always match
**both**, so user #7 and client #7 never see each other's sessions.

The `owner_id` column matches your owner models' primary key. Set `key_type` **before the first
migration** to `uuid` or `ulid` for non-integer keys; the default `bigint` creates the usual
integer column. All owner models must share that key type — a bigint `User` and a uuid
`Client` cannot share one table.

Unlike the two keys above, an **unrecognized `key_type` does not throw** — it falls back to
`bigint`. Schema shape is not a security boundary, and a one-line env typo must never leave a host
unable to migrate.

```dotenv
REFRESH_TOKENS_KEY_TYPE=ulid
```

### Absolute session lifetime

Every rotation issues the replacement with a fresh sliding `ttl`, so a continuously refreshed
session could otherwise live forever. `absolute_ttl` caps the whole rotation chain: when a family is
rooted, its hard end is stored on the row (`absolute_expires_at`, alongside `family_started_at`) and
inherited verbatim by every rotation, so each replacement's expiry is
`min(now + ttl, absolute_expires_at)`. The cap survives pruning of old rows and later config
changes. Set it to `0` (or pass `absoluteTtl: 0` for one session) to disable the cap.

### Serialization safety

The `RefreshToken` model hides `token_hash` and `access_reference` from array/JSON output
(`$hidden`), so a "your devices" endpoint that serializes session rows never leaks the at-rest
digest or the access-token reference. Auth logic reads the raw attributes directly, so nothing
internal is affected.

### Why SHA-256 (not bcrypt/argon)?

A refresh token is a 64-char CSPRNG secret drawn from the base64url alphabet — ~384 bits of
entropy. A slow password hash adds nothing against a secret that can't be brute-forced and would
break the indexed unique-equality lookup rotation relies on. Set `hash.key` to layer an HMAC pepper
on top for defence-in-depth if a database dump leaks.

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

All examples use the `RefreshTokens` facade
(`RoundlyConsulting\RefreshTokens\Facades\RefreshTokens`). The whole API at a glance:

```php
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;

RefreshTokens::for($user)->fromRequest($request)->linkedTo($jti)->issue(); // fluent issue
RefreshTokens::issue($user, new IssueContext(/* … */));                    // the same, as a DTO
RefreshTokens::redeem($plain, ownerType: $morph);   // ?RedemptionResult
RefreshTokens::rotate($plain, new RotationContext(/* … */)); // ?RotationResult
RefreshTokens::revoke($plain);                      // bool — logout with the token in hand
RefreshTokens::prune(days: 7);                      // int — force-delete dead rows

RefreshTokens::sessions($user)->all();              // active sessions, newest first
RefreshTokens::sessions($user)->find($familyId);    // ?RefreshToken
RefreshTokens::sessions($user)->revoke($familyId, RevocationReason::Logout); // bool
RefreshTokens::sessions($user)->revokeOthers($currentJti);      // int
RefreshTokens::sessions($user)->revokeAllExcept($keepFamilyId); // int
RefreshTokens::sessions($user)->revokeAll();                    // int

RefreshTokens::session($row)->enrich($device, $location); // row model or its key
RefreshTokens::session($row)->revoke(RevocationReason::Manual); // bool
```

#### Without the facade

The facade is sugar over `RoundlyConsulting\RefreshTokens\RefreshTokensManager` — inject it for
the same API, or call the action behind any method directly:

```php
use RoundlyConsulting\RefreshTokens\Actions\RotateRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\RefreshTokensManager;

final class RefreshController
{
    public function __construct(private RefreshTokensManager $refreshTokens) {}

    public function __invoke(Request $request): JsonResponse
    {
        $rotation = $this->refreshTokens->rotate($request->string('refresh_token')->value());
        // …
    }
}

// The raw action:
$rotation = app(RotateRefreshTokenAction::class)->execute($plain, new RotationContext);
```

| Facade method | Action |
|---|---|
| `issue()` / `for()->issue()` | `IssueRefreshTokenAction` |
| `redeem()` | `RedeemRefreshTokenAction` |
| `rotate()` | `RotateRefreshTokenAction` |
| `revoke()` | `RevokeRefreshTokenAction` |
| `prune()` | `PruneRefreshTokensAction` |
| `sessions()->all()` / `find()` | `ListSessionsAction` / `FindSessionAction` |
| `sessions()->revoke()` | `RevokeSessionByFamilyAction` |
| `sessions()->revokeOthers()` / `revokeAllExcept()` / `revokeAll()` | `RevokeOtherSessionsAction` / `RevokeAllSessionsExceptAction` / `RevokeAllSessionsAction` |
| `session()->enrich()` / `revoke()` | `EnrichSessionAction` / `RevokeSessionAction` |

### Issue

The host mints its access token **first**, then issues the refresh token linked to it. The
plaintext is returned **once** — never stored:

```php
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;

$new = RefreshTokens::issue($user, new IssueContext(
    ipAddress: $request->ip(),
    userAgent: $request->userAgent(),
    accessReference: $access->jti, // opaque link to the host's access token
));

$plainText = $new->plainText;      // return to the client ONCE
```

Or the fluent builder:

```php
$new = RefreshTokens::for($user)
    ->fromRequest($request)        // fills ip + user agent
    ->linkedTo($access->jti)
    ->issue();
```

Per-session options (all optional):

```php
$sid = (string) Str::uuid();       // e.g. already minted into the access token as `sid`

$new = RefreshTokens::for($client)
    ->fromRequest($request)
    ->startingFamily($sid)         // root the family under YOUR uuid (IssueContext::$newFamilyId)
    ->ttl(3600)                    // sliding lifetime for this session
    ->absoluteTtl(86_400)          // hard cap for this session; 0 = uncapped
    ->meta(['guard' => 'clients', 'amr' => ['pwd', 'otp'], 'auth_time' => time()])
    ->issue();
```

`newFamilyId` must be a well-formed UUID (checked before any query) that no family already uses,
and cannot be combined with `familyId`; each violation throws `InvalidTokenFamilyException`. Family
ids are canonicalised to lowercase, so they match case-insensitively on every driver. A
`ttl` below 1 or a negative `absoluteTtl` throws `InvalidTokenConfigurationException`.

**Session `meta`** is stored as JSON and inherited across every rotation (new keys are merged
over the old). It is readable by anyone who can read the table and is serialized with the
model — **never put secrets in it**. On Postgres (`jsonb`) object key order is not preserved.

### Rotate

`redeem()` atomically claims and rotates a token. Of N concurrent redemptions of the same
token, exactly one wins; every failure mode collapses to `null`:

```php
$result = RefreshTokens::redeem($plainFromClient); // ?RedemptionResult
if ($result === null) {
    // unknown / expired / revoked / race-lost / reuse — host maps to its own error
    throw ValidationException::withMessages([...]);
}

$owner = $result->user;           // the owner model (User, Client, …)
$familyId = $result->familyId;
```

**Guard-scoped redemption.** Pass the owner morph class your endpoint serves. A token of another
owner type is treated as unknown — `null`, **not consumed**, no reuse signal — so presenting a
user's token at the clients endpoint can neither burn the user's session nor trip reuse detection:

```php
$result = RefreshTokens::redeem($plainFromClient, ownerType: (new Client)->getMorphClass());
```

`rotate()` does redeem + issue a same-family replacement in one call (mint the new access token
first, pass its reference in a `RotationContext`):

```php
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;

$rotation = RefreshTokens::rotate($plainFromClient, new RotationContext(
    ownerType: (new User)->getMorphClass(),  // optional guard scope
    ipAddress: $request->ip(),              // current ip/ua replace the inherited ones
    userAgent: $request->userAgent(),
    accessReference: $newAccess->jti,
    ttl: 3600,                              // optional sliding-lifetime override
    meta: ['auth_time' => $authTime],       // merged over the inherited meta
));
// ?RotationResult { user, newRefreshToken (NewRefreshToken), redeemedFamilyId }
```

**What a replacement inherits.** Issuing into an existing family — via `rotate()` or an explicit
`issue(…, new IssueContext(familyId: …))` — copies the session from the family's **newest** row
(revoked or not): `family_started_at`, `absolute_expires_at`, `meta` (merged), and the device/geo
columns (`browser`, `browser_version`, `os`, `os_version`, `device_type`, `is_bot`, `country`,
`city`, `country_code`). `ip_address`/`user_agent` come from the context when given, else they are
copied too. This makes `redeem()` → mint an access token → `issue(familyId: …)` (when the
replacement must reference a jti minted *after* the redeem) behave exactly like `rotate()`.

**Failure semantics — treat `null` (or an exception) as "re-authenticate".** `rotate()` is
redeem-then-issue: the old token is consumed **before** the replacement exists, and the operation
is deliberately not rolled back on failure (un-claiming a consumed token would reopen the
double-spend window). So if the replacement can't be minted — a DB blip between redeem and issue,
the owner deleted mid-rotation, or the family being killed by a concurrent reuse response — the
call returns `null` (or throws). The client then simply holds no valid refresh token and must log
in again. This is an availability-only edge (forced re-login); no token is ever forged.

Passing an explicit `familyId` (via `IssueContext` or `->inFamily()`) is validated: the family
must already exist for **that same owner**, must not have been killed by reuse detection, and its
newest row must not have been ended by a revoke, or an `InvalidTokenFamilyException` is thrown. This prevents grafting a token into another user's — or a
dead — lineage. Normal `rotate()` inherits the redeemed token's own family, so you rarely set this
by hand.

### Reuse detection

Presenting an already-rotated token — to `redeem()`/`rotate()`, or to `revoke()` (see
[Revoke / logout](#revoke--logout)) — is a theft signal. The **entire token family** is revoked,
the host callback is invoked for every live member's access token, and a
`RefreshTokenReuseDetected` event fires — all automatically, no config switch. The family revoke
re-scans until a pass revokes nothing, and a replacement issued into a family around the moment it
is killed self-revokes, so a freshly rotated token can never survive the theft response (any race
ordering). When the replay lands while the family is **mid-rotation** — its newest row already
claimed by a refresh whose replacement is not inserted yet, so nothing is live to revoke — the
replayed row itself is marked `ReuseDetected`, and that in-flight replacement is refused (`rotate()`
returns `null`; an explicit `issue(familyId: …)` throws `InvalidTokenFamilyException`). With the
default strict `rotation.grace = 0` this includes the loser of two concurrent redemptions of the
same token. Tune `rotation.grace` if your frontend legitimately re-presents a token within a
short single-flight window.

The `RefreshTokenReuseDetected` event fires **only when the sweep actually revokes something**
(`revokedCount > 0`), so replaying one already-dead token can't spam your alerting with empty
events. **Request throttling stays host-owned** — the package does not rate-limit token
presentation; wrap your refresh endpoint in Laravel's throttle middleware to blunt replay floods.

### Revoke / logout

```php
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;

RefreshTokens::revoke($plainFromClient);            // logout with token in hand; bool, idempotent
RefreshTokens::sessions($user)->revokeAll();         // global logout — returns count revoked
RefreshTokens::sessions($user)->revokeAll(RevocationReason::CredentialsChanged);
RefreshTokens::session($row)->revoke();              // one row you hold (reason defaults to Manual)
```

`revoke($plain)` returns `true` when it ended a live session and `false` for an unknown token or
one whose session had already ended — so calling it twice is safe.

**Logging out with an already-rotated token** still ends the session. That token no longer holds
it — the session lives on in the row it was rotated into — so revoking the spent row alone would
let whoever rotated it keep refreshing. Instead:

- **Outside `rotation.grace`** the spent token is a theft signal, handled exactly like a replay at
  `redeem()`: the whole family is revoked as `ReuseDetected`, every live access reference is
  denied, `RefreshTokenReuseDetected` fires, and `revoke()` returns `true`. The reason you passed
  is not used, because the rows record why they really died.
- **Inside `rotation.grace`** (your client's own refresh racing its logout) the family's live rows
  are revoked with your reason, `SessionRevoked` fires for each, and no reuse event fires.

A session caught mid-rotation is sealed either way, so the in-flight replacement is refused.

Every revoke verb takes an optional `RevocationReason`, persisted in `revoked_reason` and carried
on `SessionRevoked`: `Rotated`, `Logout`, `LogoutAll`, `ReuseDetected`, `Expired`, `Manual`,
`CredentialsChanged`, `AccountDisabled`, `SessionLimit`, `Security`.

A session revoked **mid-rotation** — its token already redeemed, the replacement not yet issued —
has no active row for that instant. The session verbs (`sessions()->revokeAll()`,
`revokeOthers()`, `revokeAllExcept()`, `revoke()`) seal such a session too (relabel its redeemed
row with the reason, deny its access reference, fire `SessionRevoked`), so the in-flight replacement
is refused — `rotate()` returns `null`, an explicit `issue(familyId: …)` throws
`InvalidTokenFamilyException` or comes back already revoked. "Log out everywhere" cannot be outrun by
a refresh.

### Sessions

A session is a token **family**; its active row carries the device data. Row ids change on every
rotation, so address a session by its **family id** — the stable session id (and a natural `sid`
claim for your access token). `$row->sessionStartedAt()` returns when the family began.

```php
$sessions = RefreshTokens::sessions($user);

$sessions->all();                              // active rows, newest first
$sessions->find($familyId);                    // ?RefreshToken — active row of that family
$sessions->revoke($familyId);                  // bool — revokes every active row of it
$sessions->revokeAllExcept($currentFamilyId);  // "log out my other devices"; int
$sessions->revokeOthers($currentAccess->jti);  // same, keyed by access reference
$sessions->revokeAll();                        // revoke every session

// On the owner model via the trait:
$user->refreshTokens();  // MorphMany, all tokens
$user->sessions();       // MorphMany, active tokens only
```

The handle is owner-scoped: another owner's family — including one of a same-id owner of another
type — is unknown (`find()` ⇒ `null`, `revoke()` ⇒ `false`, nothing touched). Ids are validated as
UUIDs before any query (malformed ⇒ `null`/`false`, never a database error). `revoke()` revokes
**every** active row of the family — a grace-window rotation can briefly
leave two — denying each access reference once. `revokeAllExcept` with `null` or an unrecognisable
id revokes everything (fail closed).

The trait also adds `$user->…()` verbs that read as the user acting on itself. Each one delegates
to the manager, so `RefreshTokens::fake()` records them too:

```php
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;

$new = $user->issueRefreshToken(new IssueContext(accessReference: $access->jti));
$user->findSession($familyId);              // ?RefreshToken
$user->revokeSession($familyId);            // bool
$user->revokeAllSessions();                 // = RefreshTokens::sessions($user)->revokeAll(); returns count
$user->revokeOtherSessions($currentAccess->jti); // keep current, revoke the rest; returns count
```

### Log out everywhere on a password change

The canonical reaction to a credential change is to revoke every session. Wire it from your
change-password flow, or from a model observer when the password attribute is dirty — the package
ships the verb but never hooks your User model for you:

```php
// In a change-password action:
$user->update(['password' => Hash::make($newPassword)]);
$user->revokeAllSessions(RevocationReason::CredentialsChanged);

// …or via a saved observer:
User::saved(function (User $user): void {
    if ($user->wasChanged('password')) {
        $user->revokeAllSessions(RevocationReason::CredentialsChanged);
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
RefreshTokens::session($new->token)->enrich(
    new DeviceData(browser: 'Firefox', os: 'Linux', deviceType: DeviceType::Desktop, isBot: false),
    new LocationData(country: 'Slovakia', city: 'Bratislava', countryCode: 'SK', ipAddress: '203.0.113.9'),
);
```

`session()` accepts the `RefreshToken` model, an int, or a string key (an unknown key throws
`SessionNotFoundException`). **Write semantics:** it only
ever touches device/geo columns — never the auth columns. The six device columns are **always
overwritten** (an absent `DeviceData` field nulls its column), while the location columns are
written **only when a `LocationData` is supplied** — so a later device-only enrich never clobbers
previously stored geo.

### Events

Hook these on the host side; they carry ids/scalars only (never the model or plaintext).
`ownerType` is the owner's morph class, so listeners can tell account types apart:

- `RefreshTokenIssued(int|string $tokenId, string $familyId, string $ownerType, int|string $ownerId)`
  — trigger async device/geo enrichment.
- `RefreshTokenRedeemed(int|string $tokenId, string $familyId, string $ownerType, int|string $ownerId)`
  — a token was legitimately spent (rotated); hook it to audit rotations or meter session churn.
- `SessionRevoked(int|string $tokenId, string $familyId, string $ownerType, int|string $ownerId,
  RevocationReason $reason, ?string $accessReference)`.
- `RefreshTokenReuseDetected(string $familyId, string $ownerType, int|string $ownerId, int $revokedCount)`
  — theft signal for alerting; `revokedCount` reports how many live family members were revoked in
  response.

`rotate()` fires one `RefreshTokenRedeemed` (for the spent token) **and** one `RefreshTokenIssued`
(for the replacement).

### Pruning

Dead rows (revoked/expired past `prune.after`) are force-deleted by `RefreshTokens::prune()` or
the `refresh-tokens:prune` command (a thin shell over it). The package does **not** self-schedule —
the host schedules it:

```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;

Schedule::command('refresh-tokens:prune')->daily();
```

```bash
php artisan refresh-tokens:prune            # uses config('refresh-tokens.prune.after')
php artisan refresh-tokens:prune --days=7   # override retention
```

```php
RefreshTokens::prune();        // int — uses config('refresh-tokens.prune.after')
RefreshTokens::prune(days: 7); // override retention
```

`--days` / `days:` is floored at **1** (a value of `0` or a non-integer is rejected;
`prune(0)` throws `InvalidTokenConfigurationException`; a configured value below 1 is clamped). Pruning tokens revoked
less than a day ago would destroy **reuse-detection evidence**: a rotated token pruned minutes
after revocation, then re-presented by a thief, finds no row and fires no family revoke. Keep the
retention window comfortably longer than your access-token TTL so the theft signal survives.

Laravel's `model:prune` works too — the model is `Prunable`, reading the same clamped
`prune.after` window — but a bare `php artisan model:prune` only discovers models under
`app/Models`, so it never finds the package's model. Name it (or your subclass, if you swapped
`refresh-tokens.model`):

```bash
php artisan model:prune --model="RoundlyConsulting\RefreshTokens\Models\RefreshToken"
```

If you schedule `model:prune` for your own models as well, run `refresh-tokens:prune` alongside it
rather than relying on discovery.

## Security

- **SHA-256 at rest** (allowlisted SHA-2 only) under a unique index; the plaintext is returned
  once and never persisted, and `token_hash`/`access_reference` are hidden from serialization.
- **Single-query anti-double-spend** rotation (`WHERE revoked_at IS NULL` compare-and-swap) — no
  transaction, no row lock; works identically on PostgreSQL and SQLite.
- **Always-on family revocation** on reuse detection — a spent token presented to redeem *or* to
  log out — race-hardened so no rotated replacement survives the theft response and the signal
  never spams on replayed dead tokens.
- **Absolute session lifetime** (`absolute_ttl`, stored per family) caps a rotation chain so a
  stolen-but-active session can't be refreshed forever.
- **Guard-scoped redemption** (`redeem($plain, ownerType: …)`): a token presented at another
  account type's endpoint is invisible — never consumed, never counted as reuse.
- **Session `meta` is not a secret store** — it is plain JSON, serialized with the model.
- `#[SensitiveParameter]` on every plaintext parameter; plaintext and hashes are never logged.

Intentionally host-owned (not this package): JWT minting/verification, jti denylisting,
user-agent parsing, IP geolocation, HTTP routes/controllers, throttling, and cookie transport.

## Testing

`RefreshTokens::fake()` swaps the manager for a **recording** fake. Calls still run for real —
tokens are issued, redeemed and revoked in your test database, because a stub that answered
`redeem()` differently from the real store would let a broken refresh flow pass — and every call
is recorded, whether it came through the facade, an injected `RefreshTokensManager`,
`for()->issue()`, `sessions()` / `session()` or the `HasRefreshTokens` trait:

```php
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;

$fake = RefreshTokens::fake();

// … exercise your login / refresh / logout endpoints …

$fake->assertIssued(for: $user);
$fake->assertIssued($user, fn (IssueContext $context): bool => $context->accessReference === $jti);
$fake->assertRedeemed(by: $user);
$fake->assertRotated(for: $user);
$fake->assertRevoked(for: $user, reason: RevocationReason::CredentialsChanged);
$fake->assertEnriched(for: $user);
$fake->assertPruned();

$fake->assertNothingIssued();   // …and assertNothingRedeemed/Rotated/Revoked/Enriched/Pruned()
```

A rotation is recorded as a rotation only (not also as a redeem and an issue). `assertRevoked()`
matches every revoke verb — by plaintext, `sessions()->revoke…()`, `session()->revoke()` and the
trait. `$fake->recorded()` returns every call as a `RecordedOperation`.

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

<!-- roundly-support:start -->
## Support our work

This package is free and open source, built and maintained by
[Roundly Consulting](https://roundly-consulting.com/open-source?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=refresh-tokens-for-laravel).
If it saves you time, please consider supporting our open-source work — a one-time donation, a
monthly pledge on Patreon or a crypto donation helps fund maintenance, new features and new
packages.

<a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/Donate-Support%20Roundly%20open%20source-F24E29?style=for-the-badge&logo=stripe&logoColor=white" alt="Donate to Roundly open source"></a>
<a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/Patreon-Become%20a%20patron-F96854?style=for-the-badge&logo=patreon&logoColor=white" alt="Become a patron on Patreon"></a>
<a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=refresh-tokens-for-laravel#crypto"><img src="https://img.shields.io/badge/Crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate crypto: BTC, ETH, BNB or SOL"></a>
<!-- roundly-support:end -->

## License

The MIT License (MIT). Copyright (c) roundly-consulting. See [LICENSE.md](LICENSE.md).
