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
- **Polymorphic owners**: tokens hang off `owner_type` + `owner_id` (toolkit `morphKey`, composite
  index), so any `Authenticatable` model holds sessions in one table. The `user_model` and
  `foreign_key` config keys are removed; `key_type` is now the key type shared by every owner model.
  Owner parameters are typed `Authenticatable&Model`; `HasRefreshTokens` relations are `MorphMany`;
  the factory's `forUser()` is now `forOwner()`; new `ownedBy()` scope.
- **Guard-scoped redemption**: `redeem($plain, ?string $ownerType)` — a token of another owner type
  is unknown and is not consumed (no claim, no family revoke, no event).
- `rotate($plain, ?RotationContext $context)` replaces the `linkedTo` string: owner-type scope,
  current ip/ua, access reference, ttl and meta for the replacement.
- `IssueContext` gains `newFamilyId` (root a family under a caller-chosen UUID), `ttl`,
  `absoluteTtl` and `meta`; `PendingIssue` gains `startingFamily()`, `ttl()`, `absoluteTtl()`, `meta()`.
- New `family_started_at`, `absolute_expires_at` and `meta` (jsonb) columns; the absolute cap is
  stored at the root and inherited, instead of re-queried from the root row. Inheriting a family
  (rotation or explicit `familyId`) copies meta (merged), family timestamps and device/geo columns
  from the family's newest row. `RefreshTokenBlueprint::addSessionColumns()` for host adoption.
- Family-addressed sessions: `findSession()`, `revokeSession()`, `revokeAllExcept()` on the facade,
  `SessionManager` and (the first two) the trait; `RefreshToken::sessionStartedAt()`.
- `RevocationReason` gains `CredentialsChanged`, `AccountDisabled`, `SessionLimit`, `Security`;
  every revoke verb accepts a reason.
- Events carry the family and owner (`ownerType`, `ownerId`) instead of `userId`;
  `RefreshTokenIssued` gains family/owner; `SessionRevoked` gains family, owner and reason.
- Family-level revokes (`revokeAllFor`/`revokeAll`, `revokeOthers`, `revokeAllExcept`,
  `revokeSession`) seal a session caught mid-rotation, so a concurrent refresh can no longer carry
  it past the logout; inheriting a family whose newest row was ended by a revoke now throws
  `InvalidTokenFamilyException::ended`.
- A replay that lands while its family is mid-rotation now marks the family reused, so the in-flight
  replacement is refused; `rotate()` returns `null` (instead of throwing) when the family dies
  between its redeem and its issue.
