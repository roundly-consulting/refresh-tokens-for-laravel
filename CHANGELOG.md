# Changelog

All notable changes to `refresh-tokens-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- Opaque, rotating refresh tokens through the `RefreshToken` facade — `issue()` (or a fluent
  builder), `redeem()` and `rotate()` — linked to the host's own access tokens.
- SHA-256 storage at rest with an optional HMAC pepper; the plaintext is returned once and never
  persisted.
- Atomic, single-query rotation that stops double spending, with guard-scoped redemption per
  owner type.
- Always-on reuse detection: presenting a spent token revokes its whole family and fires
  `RefreshTokenReuseDetected`.
- Polymorphic owners (bigint, UUID or ULID), so users, API clients and admins share one table,
  via the `HasRefreshTokens` trait.
- Device sessions: list, find and revoke sessions (`revokeSession()`, `revokeAllExcept()`,
  `revokeOthers()`, `revokeAllFor()`) with typed `RevocationReason`s, plus `$user` verbs such as
  `revokeAllSessions()`.
- A sliding TTL with an absolute session lifetime cap, and session `meta` inherited across
  rotations.
- `RefreshToken::enrich()` to attach host-supplied device and location data to a session.
- An `AccessTokenRevoker` contract to deny linked access tokens on revocation, with a
  `FakeAccessTokenRevoker` for tests.
- `RefreshTokenIssued`, `RefreshTokenRedeemed`, `SessionRevoked` and `RefreshTokenReuseDetected`
  events carrying ids only.
- The `refresh-tokens:prune` command for revoked and expired rows.
