<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Exceptions\SessionNotFoundException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

it('enriches a session with device and location without touching auth columns', function (): void {
    $user = User::factory()->create();
    $session = RefreshTokenModel::factory()->forUser($user)->create([
        'token_hash' => hash('sha256', 'seed'),
        'access_reference' => 'acc-keep',
    ]);
    $originalHash = $session->token_hash;
    $originalFamily = $session->family_id;
    $originalExpiry = $session->expires_at;

    RefreshToken::enrich($session->getKey(), new DeviceData(
        browser: 'Firefox',
        browserVersion: '128.0',
        os: 'Linux',
        osVersion: '6.9',
        deviceType: DeviceType::Desktop,
        isBot: false,
    ), new LocationData(
        country: 'Slovakia',
        city: 'Bratislava',
        countryCode: 'SK',
        ipAddress: '203.0.113.44',
    ));

    $fresh = $session->fresh();

    expect($fresh->browser)->toBe('Firefox')
        ->and($fresh->browser_version)->toBe('128.0')
        ->and($fresh->os)->toBe('Linux')
        ->and($fresh->os_version)->toBe('6.9')
        ->and($fresh->device_type)->toBe(DeviceType::Desktop)
        ->and($fresh->is_bot)->toBeFalse()
        ->and($fresh->country)->toBe('Slovakia')
        ->and($fresh->city)->toBe('Bratislava')
        ->and($fresh->country_code)->toBe('SK')
        ->and($fresh->ip_address)->toBe('203.0.113.44')
        // Auth columns are untouched.
        ->and($fresh->token_hash)->toBe($originalHash)
        ->and($fresh->family_id)->toBe($originalFamily)
        ->and($fresh->access_reference)->toBe('acc-keep')
        ->and($fresh->revoked_at)->toBeNull()
        ->and($fresh->expires_at->equalTo($originalExpiry))->toBeTrue();
});

it('enriches device-only when no location is supplied', function (): void {
    $user = User::factory()->create();
    $session = RefreshTokenModel::factory()->forUser($user)->create();

    RefreshToken::enrich($session->getKey(), new DeviceData(deviceType: DeviceType::Mobile));

    expect($session->fresh()->device_type)->toBe(DeviceType::Mobile)
        ->and($session->fresh()->country)->toBeNull();
});

it('throws when enriching an unknown session id', function (): void {
    RefreshToken::enrich(999999, new DeviceData);
})->throws(SessionNotFoundException::class);
