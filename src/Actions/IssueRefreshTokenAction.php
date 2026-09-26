<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenIssued;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Mint a new opaque refresh token: generate a high-entropy plaintext, store only
 * its hash, root or inherit a family lineage, and return the plaintext once.
 *
 * Inheriting (`familyId`) copies the session from the family's newest row — its
 * family timestamps, `meta`, and device/geo columns — whether or not that row is
 * still active: on a refresh the row `redeem()` just claimed is already revoked
 * when the replacement is issued, and it is exactly the row to inherit from.
 *
 * When inheriting a family the action guards the theft response and every logout:
 * the family must exist for the owner and be alive before the insert — not killed by
 * reuse detection, and its newest row not ended by a revoke (a revoke seals a family
 * caught mid-rotation by relabelling that row, see {@see SealPendingRotationsAction})
 * — and, because either can land in the window around the insert, the just-inserted
 * row is re-checked and self-revoked if the family has since been killed or sealed,
 * so a rotation replacement can never outlive its family.
 */
final class IssueRefreshTokenAction
{
    /**
     * The device and geolocation columns a family carries from row to row.
     * `ip_address` and `user_agent` are handled separately: the context wins.
     */
    private const array CARRIED_COLUMNS = [
        'browser',
        'browser_version',
        'os',
        'os_version',
        'device_type',
        'is_bot',
        'country',
        'city',
        'country_code',
    ];

    public function __construct(
        private readonly TokenHasher $hasher,
    ) {}

    /**
     * @throws InvalidTokenFamilyException
     * @throws InvalidTokenConfigurationException
     */
    public function execute(Authenticatable&Model $owner, IssueContext $context): NewRefreshToken
    {
        $this->assertContextIsValid($context);

        $now = CarbonImmutable::now();

        // Family ids are uuids — case-insensitive values. Canonicalise them (lowercase,
        // as Postgres' uuid column does on its own) so every driver stores, finds and
        // de-duplicates them alike.
        $familyId = $context->familyId !== null ? strtolower($context->familyId) : null;
        $newFamilyId = $context->newFamilyId !== null ? strtolower($context->newFamilyId) : null;

        $source = $familyId !== null
            ? $this->inheritanceSource($familyId, $owner)
            : null;

        if ($newFamilyId !== null) {
            $this->assertFamilyIsNew($newFamilyId);
        }

        $plain = $this->hasher->generate();

        $token = TokenModel::make();
        $token->owner_type = $owner->getMorphClass();
        $token->owner_id = $this->ownerId($owner);
        $token->token_hash = $this->hasher->hash($plain);
        $token->family_id = $source->family_id ?? $newFamilyId ?? (string) Str::uuid();
        $token->access_reference = $context->accessReference;
        $token->ip_address = $context->ipAddress ?? $source?->ip_address;
        $token->user_agent = $context->userAgent ?? $source?->user_agent;

        if ($source !== null) {
            foreach (self::CARRIED_COLUMNS as $column) {
                $token->setAttribute($column, $source->getAttributeValue($column));
            }

            // Verbatim — a row that predates the column falls back to its own start.
            $token->family_started_at = $source->sessionStartedAt();
            $token->absolute_expires_at = $source->absolute_expires_at;
            $token->meta = $this->mergeMeta($source->meta, $context->meta);
        } else {
            $absolute = $context->absoluteTtl ?? $this->configuredAbsoluteTtl();

            $token->family_started_at = $now;
            $token->absolute_expires_at = $absolute > 0 ? $now->addSeconds($absolute) : null;
            $token->meta = $this->mergeMeta(null, $context->meta);
        }

        $token->expires_at = $this->expiresAt($now, $context->ttl ?? $this->configuredTtl(), $token->absolute_expires_at);
        $token->save();

        // Reuse detection or a revoke may have ended the family between the liveness
        // check and this insert (either ordering of insert-vs-revoke). If so, this
        // replacement must not survive it — revoke it immediately.
        if ($source !== null) {
            $this->recheckFamily($token, $source, $now);

            if ($token->revoked_at !== null) {
                return new NewRefreshToken($plain, $token);
            }
        }

        Event::dispatch(new RefreshTokenIssued(
            $token->getKey(),
            $token->family_id,
            $token->owner_type,
            $token->owner_id,
        ));

        return new NewRefreshToken($plain, $token);
    }

    /**
     * Pure input checks, run before any query so a bad context never reaches the
     * database.
     *
     * @throws InvalidTokenFamilyException
     * @throws InvalidTokenConfigurationException
     */
    private function assertContextIsValid(IssueContext $context): void
    {
        if ($context->familyId !== null && $context->newFamilyId !== null) {
            throw InvalidTokenFamilyException::ambiguous();
        }

        if ($context->ttl !== null && $context->ttl < 1) {
            throw InvalidTokenConfigurationException::invalidTtl($context->ttl);
        }

        if ($context->absoluteTtl !== null && $context->absoluteTtl < 0) {
            throw InvalidTokenConfigurationException::invalidAbsoluteTtl($context->absoluteTtl);
        }
    }

    /**
     * The row a family-inheriting issue copies its session from: the family's
     * newest row owned by this owner, by `(created_at, id)`, revoked or not.
     *
     * @throws InvalidTokenFamilyException
     */
    private function inheritanceSource(string $familyId, Authenticatable&Model $owner): RefreshToken
    {
        // `familyId` is caller-supplied (a public IssueContext parameter) and
        // `family_id` is a **uuid** column, so a malformed value can never name a live
        // family on any engine — but only a strict engine says so. Postgres rejects the
        // comparison outright (`invalid input syntax for type uuid`), so without this
        // guard a host passing a bad family id got a raw QueryException leaking database
        // internals instead of the documented InvalidTokenFamilyException. SQLite hid it
        // for the package's whole life by comparing uuid columns as text, which is why
        // the suite was green.
        //
        // Rejecting it here keeps the documented contract identical on every driver and
        // is not a new rule: it is the column's own type, enforced before the query
        // rather than by whichever engine happens to be underneath.
        if (! Str::isUuid($familyId)) {
            throw InvalidTokenFamilyException::unknownForOwner($familyId);
        }

        $source = TokenModel::query()
            ->ownedBy($owner)
            ->forFamily($familyId)
            ->latest()
            ->latest('id')
            ->first();

        if ($source === null) {
            throw InvalidTokenFamilyException::unknownForOwner($familyId);
        }

        if ($this->familyHasReuse($familyId)) {
            throw InvalidTokenFamilyException::reuseRevoked($familyId);
        }

        if ($this->endedBy($source) !== null) {
            throw InvalidTokenFamilyException::ended($familyId);
        }

        return $source;
    }

    /**
     * The reason a family's newest row says the session is over, or null while it
     * may still be extended: an active row, or one merely consumed by a rotation.
     */
    private function endedBy(RefreshToken $source): ?RevocationReason
    {
        $reason = $source->revoked_reason;

        return $source->revoked_at !== null && $reason !== null && $reason !== RevocationReason::Rotated
            ? $reason
            : null;
    }

    /**
     * Post-insert: self-revoke the replacement when the family was killed by reuse or
     * its source row was sealed by a revoke around the insert, and reflect a revoke
     * that swept the replacement itself in that window.
     */
    private function recheckFamily(RefreshToken $token, RefreshToken $source, CarbonImmutable $now): void
    {
        if ($this->familyHasReuse($token->family_id)) {
            $this->selfRevoke($token, $now, RevocationReason::ReuseDetected);

            return;
        }

        $current = TokenModel::query()->whereKey($source->getKey())->first();
        $ended = $current !== null ? $this->endedBy($current) : null;

        if ($ended !== null) {
            $this->selfRevoke($token, $now, $ended);

            return;
        }

        $stored = TokenModel::query()->whereKey($token->getKey())->first();

        if ($stored !== null && $stored->revoked_at !== null) {
            $token->revoked_at = $stored->revoked_at;
            $token->revoked_reason = $stored->revoked_reason;
        }
    }

    /**
     * A caller-chosen root id must be a well-formed UUID (checked before the query,
     * for the same strict-engine reason as above) that no family — of ANY owner —
     * already uses: family ids are the stable session identifier.
     *
     * @throws InvalidTokenFamilyException
     */
    private function assertFamilyIsNew(string $familyId): void
    {
        if (! Str::isUuid($familyId)) {
            throw InvalidTokenFamilyException::malformed($familyId);
        }

        if (TokenModel::query()->withTrashed()->forFamily($familyId)->exists()) {
            throw InvalidTokenFamilyException::alreadyExists($familyId);
        }
    }

    private function familyHasReuse(string $familyId): bool
    {
        return TokenModel::query()
            ->where('family_id', $familyId)
            ->where('revoked_reason', RevocationReason::ReuseDetected->value)
            ->exists();
    }

    private function selfRevoke(RefreshToken $token, CarbonImmutable $now, RevocationReason $reason): void
    {
        TokenModel::query()
            ->whereKey($token->getKey())
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => $now,
                'revoked_reason' => $reason->value,
            ]);

        $token->revoked_at = $now;
        $token->revoked_reason = $reason;
    }

    /**
     * The sliding TTL, clamped to the family's stored absolute end so repeated
     * rotation cannot extend a session forever.
     */
    private function expiresAt(CarbonImmutable $now, int $ttl, ?CarbonImmutable $absoluteExpiresAt): CarbonImmutable
    {
        $expiresAt = $now->addSeconds($ttl);

        if ($absoluteExpiresAt === null) {
            return $expiresAt;
        }

        return $absoluteExpiresAt->lessThan($expiresAt) ? $absoluteExpiresAt : $expiresAt;
    }

    /**
     * @param  array<string, mixed>|null  $inherited
     * @param  array<string, mixed>|null  $given
     * @return array<string, mixed>|null
     */
    private function mergeMeta(?array $inherited, ?array $given): ?array
    {
        $merged = array_merge($inherited ?? [], $given ?? []);

        return $merged === [] ? null : $merged;
    }

    /**
     * The owner's model key — not its auth identifier: `owner_id` is a morph key, and
     * `owner()` / `refreshTokens()` resolve it through the key like any Eloquent morph.
     */
    private function ownerId(Authenticatable&Model $owner): int|string
    {
        $id = $owner->getKey();

        return is_int($id) ? $id : (string) $id;
    }

    private function configuredTtl(): int
    {
        $ttl = config('refresh-tokens.ttl', 2_592_000);

        return is_int($ttl) && $ttl > 0 ? $ttl : 2_592_000;
    }

    private function configuredAbsoluteTtl(): int
    {
        $ttl = config('refresh-tokens.absolute_ttl', 7_776_000);

        return is_int($ttl) && $ttl > 0 ? $ttl : 0;
    }
}
