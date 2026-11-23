<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

use InvalidArgumentException;
use RoundlyConsulting\RefreshTokens\Enums\RedemptionFailure;

/**
 * The outcome of `RefreshTokens::attempt()`: the redemption's result when it succeeded,
 * else why it failed — `Superseded` (rotated moments ago, the session lives on) or
 * `Refused` (anything else).
 */
final readonly class RedemptionAttempt
{
    /**
     * @throws InvalidArgumentException when the result and the failure disagree
     */
    public function __construct(
        public ?RedemptionResult $result,
        public RedemptionFailure $failure,
    ) {
        if (($result === null) === ($failure === RedemptionFailure::None)) {
            throw new InvalidArgumentException('A redemption attempt carries a result exactly when it did not fail.');
        }
    }

    public static function won(RedemptionResult $result): self
    {
        return new self($result, RedemptionFailure::None);
    }

    public static function failed(RedemptionFailure $failure): self
    {
        return new self(null, $failure);
    }

    /**
     * Whether the token was redeemed; `$result` is then set.
     *
     * @phpstan-assert-if-true RedemptionResult $this->result
     */
    public function succeeded(): bool
    {
        return $this->failure === RedemptionFailure::None;
    }

    /**
     * Whether the token was rotated moments ago and its session lives on: keep the newer
     * token the concurrent refresh handed out rather than ending the session.
     */
    public function superseded(): bool
    {
        return $this->failure === RedemptionFailure::Superseded;
    }
}
