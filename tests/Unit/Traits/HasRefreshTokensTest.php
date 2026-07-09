<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

it('exposes the refreshTokens relation against the configured foreign key', function (): void {
    $user = User::factory()->create();
    RefreshToken::factory()->forUser($user)->count(2)->create();
    RefreshToken::factory()->forUser(User::factory()->create())->create();

    expect($user->refreshTokens()->count())->toBe(2);
});

it('exposes only active tokens as sessions', function (): void {
    $user = User::factory()->create();
    RefreshToken::factory()->forUser($user)->create();
    RefreshToken::factory()->forUser($user)->expired()->create();
    RefreshToken::factory()->forUser($user)->revoked()->create();

    expect($user->sessions()->count())->toBe(1);
});
