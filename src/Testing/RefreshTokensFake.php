<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Testing;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Assert;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\RefreshTokensManager;
use RoundlyConsulting\RefreshTokens\Support\OwnerSessions;
use RoundlyConsulting\RefreshTokens\Support\SessionHandle;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use SensitiveParameter;

/**
 * A recording, still-performing {@see RefreshTokensManager}, installed by
 * `RefreshTokens::fake()`. Tokens are really issued, redeemed and revoked — a refresh
 * token is a security primitive, and a stub that answered `redeem()` differently from
 * the real store would let a broken flow pass — and every call is recorded for the
 * `assert*()` helpers below, whether it came through the facade, an injected manager,
 * `for()->issue()`, `sessions()` / `session()`, or the `HasRefreshTokens` trait.
 *
 * A rotation is recorded as a rotation only — not also as a redeem and an issue.
 */
final class RefreshTokensFake extends RefreshTokensManager
{
    /** @var list<RecordedOperation> */
    private array $recorded = [];

    public function __construct(Container $container)
    {
        parent::__construct($container);
    }

    public function issue(Authenticatable&Model $owner, IssueContext $context): NewRefreshToken
    {
        $issued = parent::issue($owner, $context);

        $this->record(new RecordedOperation(RecordedOperation::ISSUE, $owner, context: $context, count: 1));

        return $issued;
    }

    public function redeem(#[SensitiveParameter] string $plain, ?string $ownerType = null): ?RedemptionResult
    {
        $result = parent::redeem($plain, $ownerType);

        $this->record(new RecordedOperation(RecordedOperation::REDEEM, $result?->user, count: $result === null ? 0 : 1));

        return $result;
    }

    public function rotate(#[SensitiveParameter] string $plain, ?RotationContext $context = null): ?RotationResult
    {
        $result = parent::rotate($plain, $context);

        $this->record(new RecordedOperation(RecordedOperation::ROTATE, $result?->user, count: $result === null ? 0 : 1));

        return $result;
    }

    public function revoke(#[SensitiveParameter] string $plain, RevocationReason $reason = RevocationReason::Logout): bool
    {
        $owner = TokenModel::query()
            ->where('token_hash', $this->container->make(TokenHasher::class)->hash($plain))
            ->first()
            ?->owner;

        $revoked = parent::revoke($plain, $reason);

        $this->record(new RecordedOperation(
            RecordedOperation::REVOKE,
            $owner instanceof Model ? $owner : null,
            $reason,
            count: $revoked ? 1 : 0,
        ));

        return $revoked;
    }

    public function sessions(Authenticatable&Model $owner): OwnerSessions
    {
        return new RecordingOwnerSessions($this, $this->container, $owner);
    }

    public function session(RefreshToken|int|string $session): SessionHandle
    {
        return new RecordingSessionHandle($this, $this->container, $session);
    }

    public function prune(?int $days = null): int
    {
        $deleted = parent::prune($days);

        $this->record(new RecordedOperation(RecordedOperation::PRUNE, count: $deleted));

        return $deleted;
    }

    /**
     * Record a performed call. Used by the recording sub-accessors.
     *
     * @internal
     */
    public function record(RecordedOperation $operation): void
    {
        $this->recorded[] = $operation;
    }

    /**
     * Every recorded call, in order.
     *
     * @return list<RecordedOperation>
     */
    public function recorded(): array
    {
        return $this->recorded;
    }

    /**
     * @param  (Closure(IssueContext): bool)|null  $where
     */
    public function assertIssued(?Model $for = null, ?Closure $where = null): void
    {
        $matches = array_filter(
            $this->matching(RecordedOperation::ISSUE, $for),
            static fn (RecordedOperation $op): bool => $where === null || ($op->context !== null && $where($op->context) === true),
        );

        Assert::assertNotSame([], $matches, 'Expected a matching refresh token to be issued'.$this->forWhom($for).', but none was.');
    }

    public function assertNothingIssued(): void
    {
        $this->assertNone(RecordedOperation::ISSUE, 'issued');
    }

    public function assertRedeemed(?Model $by = null): void
    {
        Assert::assertNotSame(
            [],
            $this->matching(RecordedOperation::REDEEM, $by),
            'Expected a refresh token to be redeemed'.$this->forWhom($by).', but none was.',
        );
    }

    public function assertNothingRedeemed(): void
    {
        $this->assertNone(RecordedOperation::REDEEM, 'redeemed');
    }

    public function assertRotated(?Model $for = null): void
    {
        Assert::assertNotSame(
            [],
            $this->matching(RecordedOperation::ROTATE, $for),
            'Expected a refresh token to be rotated'.$this->forWhom($for).', but none was.',
        );
    }

    public function assertNothingRotated(): void
    {
        $this->assertNone(RecordedOperation::ROTATE, 'rotated');
    }

    /**
     * A revoke call of any kind: by plaintext, `sessions($owner)->revoke…()`,
     * `session($row)->revoke()` or a `HasRefreshTokens` verb.
     */
    public function assertRevoked(?Model $for = null, ?RevocationReason $reason = null): void
    {
        $matches = array_filter(
            $this->matching(RecordedOperation::REVOKE, $for),
            static fn (RecordedOperation $op): bool => $reason === null || $op->reason === $reason,
        );

        Assert::assertNotSame(
            [],
            $matches,
            'Expected a revoke'.$this->forWhom($for).($reason === null ? '' : " with reason [{$reason->value}]").', but none was recorded.',
        );
    }

    public function assertNothingRevoked(): void
    {
        $this->assertNone(RecordedOperation::REVOKE, 'revoked');
    }

    public function assertEnriched(?Model $for = null): void
    {
        Assert::assertNotSame(
            [],
            $this->matching(RecordedOperation::ENRICH, $for),
            'Expected a session to be enriched'.$this->forWhom($for).', but none was.',
        );
    }

    public function assertNothingEnriched(): void
    {
        $this->assertNone(RecordedOperation::ENRICH, 'enriched');
    }

    public function assertPruned(): void
    {
        Assert::assertNotSame([], $this->matching(RecordedOperation::PRUNE, null), 'Expected refresh tokens to be pruned, but prune() was never called.');
    }

    public function assertNothingPruned(): void
    {
        $this->assertNone(RecordedOperation::PRUNE, 'pruned');
    }

    /**
     * @return list<RecordedOperation>
     */
    private function matching(string $operation, ?Model $owner): array
    {
        return array_values(array_filter(
            $this->recorded,
            static fn (RecordedOperation $op): bool => $op->operation === $operation
                && ($owner === null || $op->isOwnedBy($owner)),
        ));
    }

    private function assertNone(string $operation, string $verb): void
    {
        $count = count($this->matching($operation, null));

        Assert::assertSame(0, $count, "Expected nothing to be {$verb}, but {$count} call(s) were recorded.");
    }

    private function forWhom(?Model $owner): string
    {
        return $owner === null ? '' : ' for ['.$owner->getMorphClass().'#'.$owner->getKey().']';
    }
}
