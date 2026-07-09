<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

interface SessionManager
{
    /**
     * Active sessions for the user, newest first.
     *
     * @return Collection<int, RefreshToken>
     */
    public function listFor(Authenticatable $user): Collection;

    /** Revoke one session; idempotent, denies its access reference once. */
    public function revoke(RefreshToken $session): void;

    /** Revoke every active session except the one holding the current access reference. */
    public function revokeOthers(Authenticatable $user, ?string $currentAccessReference): int;

    /** Revoke every active session for the user (= revokeOthers with no current reference). */
    public function revokeAll(Authenticatable $user): int;

    /**
     * Write device/geo columns onto a session (by model or by key); never touches
     * auth columns. Device columns are always overwritten (an absent field nulls its
     * column); location columns are written only when a $location is supplied.
     */
    public function enrich(RefreshToken|int|string $session, DeviceData $device, ?LocationData $location = null): void;
}
