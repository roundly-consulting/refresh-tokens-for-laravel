<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\RefreshTokens\Actions\EnrichSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeSessionAction;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Exceptions\SessionNotFoundException;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Testing\RecordingSessionHandle;

/**
 * One session row — `RefreshTokens::session($row)`, by model or by key (e.g. from a
 * queued job that stored the id). A key naming no row throws
 * {@see SessionNotFoundException}.
 *
 * Not final: {@see RecordingSessionHandle} extends it under `RefreshTokens::fake()`.
 */
readonly class SessionHandle
{
    public function __construct(
        protected Container $container,
        public RefreshToken|int|string $session,
    ) {}

    /**
     * Write device/geo columns onto the session; never touches auth columns. Device
     * columns are always overwritten (an absent field nulls its column); location
     * columns only when a `$location` is given.
     */
    public function enrich(DeviceData $device, ?LocationData $location = null): void
    {
        $this->container->make(EnrichSessionAction::class)->execute($this->session, $device, $location);
    }

    /**
     * Revoke this row and deny its access reference once. Idempotent: false when it was
     * already revoked.
     */
    public function revoke(RevocationReason $reason = RevocationReason::Manual): bool
    {
        return $this->container->make(RevokeSessionAction::class)->execute($this->session, $reason);
    }
}
