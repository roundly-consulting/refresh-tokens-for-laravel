<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\Exceptions\SessionNotFoundException;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Write host-supplied device and geolocation metadata onto a session. Only ever
 * touches the device/geo columns — never the auth columns (token_hash, revoked_at,
 * expires_at, access_reference, family_id).
 *
 * Write semantics: the six device columns are always overwritten, so an absent
 * {@see DeviceData} field nulls its column. Location columns are written only when a
 * {@see LocationData} is supplied, so a device-only enrich never clobbers previously
 * stored geo.
 */
final class EnrichSessionAction
{
    public function execute(RefreshToken|int|string $session, DeviceData $device, ?LocationData $location = null): void
    {
        $sessionId = $session instanceof RefreshToken ? $session->getKey() : $session;

        $session = TokenModel::query()->whereKey($sessionId)->first();

        if ($session === null) {
            throw SessionNotFoundException::forId($sessionId);
        }

        $session->browser = $device->browser;
        $session->browser_version = $device->browserVersion;
        $session->os = $device->os;
        $session->os_version = $device->osVersion;
        $session->device_type = $device->deviceType;
        $session->is_bot = $device->isBot;

        if ($location !== null) {
            $session->country = $location->country;
            $session->city = $location->city;
            $session->country_code = $location->countryCode;
            $session->ip_address = $location->ipAddress;
        }

        $session->save();
    }
}
