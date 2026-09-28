<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Support\OwnerSessions;
use SensitiveParameter;

/**
 * The `sessions($owner)` sub-accessor under `RefreshTokens::fake()`: every revoke runs
 * for real and is then recorded against the owner. Reads are not recorded.
 */
final readonly class RecordingOwnerSessions extends OwnerSessions
{
    public function __construct(
        private RefreshTokensFake $fake,
        Container $container,
        Authenticatable&Model $owner,
    ) {
        parent::__construct($container, $owner);
    }

    public function revoke(string $familyId, RevocationReason $reason = RevocationReason::Logout): bool
    {
        $revoked = parent::revoke($familyId, $reason);

        $this->recorded($reason, $revoked ? 1 : 0);

        return $revoked;
    }

    public function revokeOthers(
        #[SensitiveParameter] ?string $currentAccessReference,
        RevocationReason $reason = RevocationReason::LogoutAll,
    ): int {
        return $this->recorded($reason, parent::revokeOthers($currentAccessReference, $reason));
    }

    public function revokeAllExcept(?string $keepFamilyId, RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return $this->recorded($reason, parent::revokeAllExcept($keepFamilyId, $reason));
    }

    public function revokeAll(RevocationReason $reason = RevocationReason::LogoutAll): int
    {
        return $this->recorded($reason, parent::revokeAll($reason));
    }

    private function recorded(RevocationReason $reason, int $count): int
    {
        $this->fake->record(new RecordedOperation(RecordedOperation::REVOKE, $this->owner, $reason, count: $count));

        return $count;
    }
}
