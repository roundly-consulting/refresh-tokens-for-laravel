<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenIssued;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Events\SessionRevoked;

it('defaults every IssueContext field to null', function (): void {
    $context = new IssueContext;

    expect($context->ipAddress)->toBeNull()
        ->and($context->userAgent)->toBeNull()
        ->and($context->accessReference)->toBeNull()
        ->and($context->familyId)->toBeNull();
});

it('carries device and location metadata', function (): void {
    $device = new DeviceData(browser: 'Safari', deviceType: DeviceType::Tablet, isBot: false);
    $location = new LocationData(country: 'Slovakia', countryCode: 'SK');

    expect($device->browser)->toBe('Safari')
        ->and($device->deviceType)->toBe(DeviceType::Tablet)
        ->and($device->isBot)->toBeFalse()
        ->and($location->country)->toBe('Slovakia')
        ->and($location->countryCode)->toBe('SK');
});

it('carries event payloads as scalars', function (): void {
    expect((new RefreshTokenIssued(7))->tokenId)->toBe(7)
        ->and((new SessionRevoked(7, 'acc'))->accessReference)->toBe('acc')
        ->and((new RefreshTokenReuseDetected('fam', 3))->familyId)->toBe('fam')
        ->and((new RefreshTokenReuseDetected('fam', 3))->userId)->toBe(3);
});
