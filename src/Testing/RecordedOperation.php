<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Testing;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;

/**
 * One call recorded by {@see RefreshTokensFake}. `owner` is the token owner when it is
 * known — the issuing owner, the redeemed/rotated token's owner, the session's owner —
 * and null otherwise (an unknown plaintext, a prune). `count` is how many sessions or
 * rows the call ended or deleted.
 */
final readonly class RecordedOperation
{
    public const string ISSUE = 'issue';

    public const string REDEEM = 'redeem';

    public const string ROTATE = 'rotate';

    public const string REVOKE = 'revoke';

    public const string ENRICH = 'enrich';

    public const string PRUNE = 'prune';

    public function __construct(
        public string $operation,
        public ?Model $owner = null,
        public ?RevocationReason $reason = null,
        public ?IssueContext $context = null,
        public int $count = 0,
    ) {}

    public function isOwnedBy(Model $owner): bool
    {
        return $this->owner !== null
            && $this->owner->getMorphClass() === $owner->getMorphClass()
            && (string) $this->owner->getKey() === (string) $owner->getKey();
    }
}
