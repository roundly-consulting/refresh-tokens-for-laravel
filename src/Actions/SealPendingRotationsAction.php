<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\SessionRevoked;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * End the sessions a revoke would otherwise miss: those caught mid-rotation.
 *
 * A refresh claims its family's newest row (revoked, reason `Rotated`) before the
 * replacement exists — on the redeem → mint → issue path that window spans the
 * access-token mint. For that instant the session has no active row, so a revoke that
 * sweeps active rows finds nothing and the replacement then carries the session past
 * the logout. Sealing relabels such a row — the newest of its family, `Rotated`, not
 * yet expired — with the revoke's reason, denies its access reference and announces
 * the end like any revoke; the replacement's own family check (before and after its
 * insert) then refuses to extend the sealed family.
 *
 * Callers seal BEFORE sweeping active rows: a replacement inserted before the seal
 * looks is caught by that sweep, one inserted after it finds its family sealed.
 */
final class SealPendingRotationsAction
{
    public function __construct(
        private readonly AccessTokenRevoker $revoker,
    ) {}

    /**
     * @param  Builder<RefreshToken>  $scope  the (owner-scoped) rows to consider
     * @param  (Closure(RefreshToken): bool)|null  $keep  sessions to leave alone
     * @return int the number of sessions sealed
     */
    public function execute(Builder $scope, RevocationReason $reason, ?Closure $keep = null): int
    {
        $table = TokenModel::table();

        /** @var Collection<int, RefreshToken> $pending */
        $pending = $scope
            ->where('revoked_reason', RevocationReason::Rotated->value)
            ->where('expires_at', '>', CarbonImmutable::now())
            ->whereNotExists(function (QueryBuilder $successors) use ($table): void {
                $successors
                    ->from($table, 'successor')
                    ->whereColumn('successor.family_id', $table.'.family_id')
                    ->whereColumn('successor.id', '>', $table.'.id');
            })
            ->get();

        $sealed = 0;

        foreach ($pending as $row) {
            if ($keep !== null && $keep($row)) {
                continue;
            }

            // Conditional, like every revoke: a concurrent seal or reuse verdict wins once.
            $claimed = TokenModel::query()
                ->whereKey($row->getKey())
                ->where('revoked_reason', RevocationReason::Rotated->value)
                ->update(['revoked_reason' => $reason->value]);

            if ($claimed === 0) {
                continue;
            }

            $sealed++;

            if ($row->access_reference !== null) {
                $this->revoker->revoke($row->access_reference);
            }

            Event::dispatch(new SessionRevoked(
                $row->getKey(),
                $row->family_id,
                $row->owner_type,
                $row->owner_id,
                $reason,
                $row->access_reference,
            ));
        }

        return $sealed;
    }
}
