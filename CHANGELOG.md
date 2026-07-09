# Changelog

All notable changes to `refresh-tokens-for-laravel` will be documented in this file.

## 1.0.0 - Unreleased

- Initial release: opaque rotating refresh tokens and device sessions with SHA-256 at rest,
  atomic single-query anti-double-spend rotation, always-on family revocation on reuse
  detection, session management, an overridable model, a facade + fluent issue/rotate API,
  typed events, and a prune command. Zero third-party runtime dependencies.
