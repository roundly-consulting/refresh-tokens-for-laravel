# Changelog

All notable changes to `refresh-tokens-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Fixed

- `issue()` refuses an `accessReference` longer than the 64-byte `access_reference` column with
  `InvalidTokenConfigurationException`, before any query. SQLite used to store it while
  PostgreSQL and strict MySQL raised a raw `QueryException`.
- `rotate()` raises input and config errors — a `RotationContext` `ttl` below 1, an
  `accessReference` over 64 bytes, an invalid `ttl`, `absolute_ttl` or `token_length` config — as
  `InvalidTokenConfigurationException` before it spends the presented token. It used to claim the
  token first, so the client's retry counted as reuse and logged the user out. `issue()` now reads
  the same config before its first query.

### Security

- Reuse detection writes its verdict on the family before it scans for live members. A rotation
  replacement inserted between that scan and the verdict used to pass every family check and
  survive the theft response as a live session until its next refresh.
- The theft response also closes a session caught mid-rotation (its newest token claimed by a
  refresh whose replacement is not issued yet): that row is relabelled `ReuseDetected`, its access
  token is denied through the `AccessTokenRevoker`, and `SessionRevoked` fires. Before, the access
  token outlived the verdict. The redeem and logout (`revoke($plain)`) paths behave the same.
- **Event semantics:** `RefreshTokenReuseDetected` now fires for that case too, with the sealed
  session counted in `revokedCount` (≥ 1). It used to fire only when a live row was revoked, so
  whether a theft raised an alert depended on timing. A replay into a family that is already over
  still fires nothing.

## 1.0.0 - 2026-10-03

Initial public release.

### Added

- Opaque, rotating refresh tokens through the `RefreshTokens` facade — `issue()` (or the fluent
  `for($owner)->…->issue()` builder), `redeem()`, `rotate()` and `revoke($plain)` — linked to the
  host's own access tokens. The facade is sugar over the injectable `RefreshTokensManager`; every
  method is backed by an action class (`RotateRefreshTokenAction`, `RevokeRefreshTokenAction`, …).
- SHA-256 storage at rest with an optional HMAC pepper; the plaintext is returned once and never
  persisted.
- Atomic, single-query rotation that stops double spending, with guard-scoped redemption per
  owner type.
- Always-on reuse detection: presenting a spent token — to redeem it or to log out with it —
  revokes its whole family and fires `RefreshTokenReuseDetected`.
- Polymorphic owners (bigint, UUID or ULID), so users, API clients and admins share one table,
  via the `HasRefreshTokens` trait.
- Device sessions through the owner-scoped `RefreshTokens::sessions($owner)` handle — `all()`,
  `find()`, `revoke()`, `revokeOthers()`, `revokeAllExcept()`, `revokeAll()` — with typed
  `RevocationReason`s, plus `$user` verbs such as `revokeAllSessions()` that delegate to it.
- A sliding TTL with an absolute session lifetime cap, and session `meta` inherited across
  rotations.
- `RefreshTokens::session($row)` — `enrich()` host-supplied device and location data onto a
  session, or `revoke()` that one row (by model or key).
- An `AccessTokenRevoker` contract to deny linked access tokens on revocation, with a
  `FakeAccessTokenRevoker` for tests.
- `RefreshTokenIssued`, `RefreshTokenRedeemed`, `SessionRevoked` and `RefreshTokenReuseDetected`
  events carrying ids only.
- `RefreshTokens::prune(?days)` and the `refresh-tokens:prune` command for revoked and expired
  rows, plus a `Prunable` model for `model:prune --model=…` (retention floored at one day on
  every path).
- `RefreshTokens::fake()` — a recording, still-performing fake with `assertIssued(for:)`,
  `assertRedeemed()`, `assertRotated()`, `assertRevoked(for:, reason:)`, `assertEnriched()`,
  `assertPruned()` and an `assertNothing…()` for each; it records calls made through the facade,
  the injected manager, the sub-accessors and the `HasRefreshTokens` trait.

### Changed (since the pre-release API)

- Facade `RefreshToken` → `RefreshTokens` (and the `RefreshTokens` alias); the root
  `RefreshTokens` → `RefreshTokensManager`. The `RefreshTokenManager` and `SessionManager`
  contracts are removed — inject `RefreshTokensManager`.
- Flat session verbs moved onto handles: `listFor()` → `sessions($o)->all()`, `findSession()` →
  `sessions($o)->find()`, `revokeSession()` → `sessions($o)->revoke()`, `revokeAllExcept()` /
  `revokeOthers()` → `sessions($o)->…`, `revokeAll()` / `revokeAllFor()` →
  `sessions($o)->revokeAll()`, `enrich()` → `session($row)->enrich()`, `revoke($row)` →
  `session($row)->revoke()`. `revoke()` now takes a plaintext only and returns `bool`.
- `refresh-tokens:prune` prints the count only.
