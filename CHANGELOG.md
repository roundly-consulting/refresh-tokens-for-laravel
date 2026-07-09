# Changelog

All notable changes to `refresh-tokens-for-laravel` will be documented in this file.

## 1.0.0 - Unreleased

- Initial release: opaque rotating refresh tokens and device sessions with SHA-256 at rest,
  atomic single-query anti-double-spend rotation, always-on family revocation on reuse
  detection, session management, an overridable model, a facade + fluent issue/rotate API,
  typed events, and a prune command. Zero third-party runtime dependencies.
- First-class, documented HMAC pepper: set `hash.key` to store an HMAC-SHA-256 digest at rest
  (defence-in-depth); default stays plain SHA-256. A whitespace-only key is treated as unset.
- New `RefreshTokenRedeemed` event fired on a successful redeem/rotate, and a `revokedCount` on
  `RefreshTokenReuseDetected` reporting how many family members were revoked.
- `HasRefreshTokens` trait verbs: `issueRefreshToken()`, `revokeAllSessions()`,
  `revokeOtherSessions()`, plus a "log out everywhere on password change" recipe in the README.
- Shipped `RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker` testing double with
  `assertRevoked` / `assertNotRevoked` / `assertNothingRevoked` / `assertRevokedCount` helpers.
- `enrich()` now accepts the `RefreshToken` model as well as an id, with documented write
  semantics (device columns always overwritten; location written only when supplied).
