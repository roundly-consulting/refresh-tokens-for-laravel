<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Testing;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\SessionHandle;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * The `session($row)` sub-accessor under `RefreshTokens::fake()`: enrich and revoke run
 * for real and are then recorded against the session's owner.
 */
final readonly class RecordingSessionHandle extends SessionHandle
{
    public function __construct(
        private RefreshTokensFake $fake,
        Container $container,
        RefreshToken|int|string $session,
    ) {
        parent::__construct($container, $session);
    }

    public function enrich(DeviceData $device, ?LocationData $location = null): void
    {
        parent::enrich($device, $location);

        $this->fake->record(new RecordedOperation(RecordedOperation::ENRICH, $this->owner(), count: 1));
    }

    public function revoke(RevocationReason $reason = RevocationReason::Manual): bool
    {
        $revoked = parent::revoke($reason);

        $this->fake->record(new RecordedOperation(RecordedOperation::REVOKE, $this->owner(), $reason, count: $revoked ? 1 : 0));

        return $revoked;
    }

    private function owner(): ?Model
    {
        $row = $this->session instanceof RefreshToken
            ? $this->session
            : TokenModel::query()->whereKey($this->session)->first();

        $owner = $row?->owner;

        return $owner instanceof Model ? $owner : null;
    }
}
