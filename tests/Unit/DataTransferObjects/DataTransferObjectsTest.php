<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenIssued;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenRedeemed;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Events\SessionRevoked;

it('defaults every IssueContext field to null', function (): void {
    $context = new IssueContext;

    expect($context->ipAddress)->toBeNull()
        ->and($context->userAgent)->toBeNull()
        ->and($context->accessReference)->toBeNull()
        ->and($context->familyId)->toBeNull()
        ->and($context->newFamilyId)->toBeNull()
        ->and($context->ttl)->toBeNull()
        ->and($context->absoluteTtl)->toBeNull()
        ->and($context->meta)->toBeNull();
});

it('defaults every RotationContext field to null and carries what it is given', function (): void {
    $empty = new RotationContext;
    $full = new RotationContext(
        ownerType: 'clients',
        ipAddress: '203.0.113.1',
        userAgent: 'UA/1',
        accessReference: 'jti-1',
        ttl: 60,
        meta: ['amr' => ['pwd']],
    );

    expect($empty->ownerType)->toBeNull()
        ->and($empty->ipAddress)->toBeNull()
        ->and($empty->userAgent)->toBeNull()
        ->and($empty->accessReference)->toBeNull()
        ->and($empty->ttl)->toBeNull()
        ->and($empty->meta)->toBeNull()
        ->and($full->ownerType)->toBe('clients')
        ->and($full->accessReference)->toBe('jti-1')
        ->and($full->ttl)->toBe(60)
        ->and($full->meta)->toBe(['amr' => ['pwd']]);
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
    $issued = new RefreshTokenIssued(7, 'fam', 'users', 3);
    $redeemed = new RefreshTokenRedeemed(7, 'fam', 'users', 3);
    $reuse = new RefreshTokenReuseDetected('fam', 'clients', 'c-9', 2);
    $revoked = new SessionRevoked(7, 'fam', 'users', 3, RevocationReason::Security, 'acc');

    expect([$issued->tokenId, $issued->familyId, $issued->ownerType, $issued->ownerId])->toBe([7, 'fam', 'users', 3])
        ->and([$redeemed->tokenId, $redeemed->familyId, $redeemed->ownerType, $redeemed->ownerId])->toBe([7, 'fam', 'users', 3])
        ->and([$reuse->familyId, $reuse->ownerType, $reuse->ownerId, $reuse->revokedCount])->toBe(['fam', 'clients', 'c-9', 2])
        ->and((new RefreshTokenReuseDetected('fam', 'users', 1))->revokedCount)->toBe(0)
        ->and($revoked->reason)->toBe(RevocationReason::Security)
        ->and($revoked->accessReference)->toBe('acc')
        ->and($revoked->familyId)->toBe('fam')
        ->and((new SessionRevoked(7, 'fam', 'users', 3, RevocationReason::Logout))->accessReference)->toBeNull();
});
