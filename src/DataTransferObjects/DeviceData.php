<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

use RoundlyConsulting\RefreshTokens\Enums\DeviceType;

/**
 * Already-parsed device metadata supplied by the host (e.g. from a user-agent
 * parser) to enrich a session. This package never parses a user agent itself.
 */
final readonly class DeviceData
{
    public function __construct(
        public ?string $browser = null,
        public ?string $browserVersion = null,
        public ?string $os = null,
        public ?string $osVersion = null,
        public DeviceType|string|null $deviceType = null,
        public ?bool $isBot = null,
    ) {}
}
