<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use SensitiveParameter;

/**
 * Sessions of any Authenticatable owner model. A session's stable id is its
 * family id (`family_id`), which survives rotation; a row id changes on every
 * refresh.
 */
interface SessionManager
{
    /**
     * Active sessions for the owner, newest first.
     *
     * @return Collection<int, RefreshToken>
     */
    public function listFor(Authenticatable&Model $owner): Collection;

    /** The active row of one of the owner's families; null when malformed, unknown, dead or foreign. */
    public function findSession(Authenticatable&Model $owner, string $familyId): ?RefreshToken;

    /** Revoke every active row of one of the owner's families (sealing it if caught mid-rotation); false when nothing was revoked. */
    public function revokeSession(Authenticatable&Model $owner, string $familyId, RevocationReason $reason = RevocationReason::Logout): bool;

    /** Revoke every active (or mid-rotation) session except the given family (null = all); returns the count ended. */
    public function revokeAllExcept(Authenticatable&Model $owner, ?string $keepFamilyId, RevocationReason $reason = RevocationReason::LogoutAll): int;

    /** Revoke one session row; idempotent, denies its access reference once. */
    public function revoke(RefreshToken $session, RevocationReason $reason = RevocationReason::Manual): void;

    /** Revoke every active session except the one holding the current access reference. */
    public function revokeOthers(Authenticatable&Model $owner, #[SensitiveParameter] ?string $currentAccessReference, RevocationReason $reason = RevocationReason::LogoutAll): int;

    /** Revoke every active session for the owner (= revokeOthers with no current reference). */
    public function revokeAll(Authenticatable&Model $owner, RevocationReason $reason = RevocationReason::LogoutAll): int;

    /**
     * Write device/geo columns onto a session (by model or by key); never touches
     * auth columns. Device columns are always overwritten (an absent field nulls its
     * column); location columns are written only when a $location is supplied.
     */
    public function enrich(RefreshToken|int|string $session, DeviceData $device, ?LocationData $location = null): void;
}
