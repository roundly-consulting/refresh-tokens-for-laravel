<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;

it('exposes translated labels for revocation reasons', function (): void {
    expect(RevocationReason::Rotated->label())->toBe('Rotated')
        ->and(RevocationReason::ReuseDetected->readable())->toBe('Reuse Detected')
        ->and(RevocationReason::LogoutAll->label())->toBe('Logout All');
});

it('enumerates every revocation reason', function (): void {
    expect(RevocationReason::values()->all())->toBe([
        'rotated', 'logout', 'logout_all', 'reuse_detected', 'expired', 'manual',
    ]);
});

it('builds select options for device types', function (): void {
    $options = DeviceType::options();

    expect($options)->toHaveCount(5)
        ->and($options->first()->value)->toBe('desktop')
        ->and(DeviceType::Mobile->label())->toBe('Mobile');
});
