<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

/**
 * Already-resolved geolocation metadata supplied by the host (e.g. from an IP
 * geolocation lookup) to enrich a session. This package never performs a lookup.
 */
final readonly class LocationData
{
    public function __construct(
        public ?string $country = null,
        public ?string $city = null,
        public ?string $countryCode = null,
        public ?string $ipAddress = null,
    ) {}
}
