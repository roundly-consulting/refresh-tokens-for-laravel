<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Exceptions\RevokerAssertionFailedException;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;

it('captures every revoked access reference', function (): void {
    $fake = new FakeAccessTokenRevoker;

    $fake->revoke('acc-1');
    $fake->revoke('acc-2');

    expect($fake->revoked)->toBe(['acc-1', 'acc-2']);
});

it('passes assertRevoked / assertRevokedCount for captured references', function (): void {
    $fake = new FakeAccessTokenRevoker;
    $fake->revoke('acc-1');
    $fake->revoke('acc-2');

    $fake->assertRevoked('acc-1');
    $fake->assertRevoked('acc-2');
    $fake->assertNotRevoked('acc-3');
    $fake->assertRevokedCount(2);

    expect(true)->toBeTrue();
});

it('passes assertNothingRevoked when idle', function (): void {
    (new FakeAccessTokenRevoker)->assertNothingRevoked();

    expect(true)->toBeTrue();
});

it('throws assertRevoked for an absent reference', function (): void {
    (new FakeAccessTokenRevoker)->assertRevoked('missing');
})->throws(RevokerAssertionFailedException::class);

it('throws assertNotRevoked for a captured reference', function (): void {
    $fake = new FakeAccessTokenRevoker;
    $fake->revoke('acc-1');

    $fake->assertNotRevoked('acc-1');
})->throws(RevokerAssertionFailedException::class);

it('throws assertNothingRevoked when something was revoked', function (): void {
    $fake = new FakeAccessTokenRevoker;
    $fake->revoke('acc-1');

    $fake->assertNothingRevoked();
})->throws(RevokerAssertionFailedException::class);

it('throws assertRevokedCount on a mismatch', function (): void {
    $fake = new FakeAccessTokenRevoker;
    $fake->revoke('acc-1');

    $fake->assertRevokedCount(2);
})->throws(RevokerAssertionFailedException::class);
