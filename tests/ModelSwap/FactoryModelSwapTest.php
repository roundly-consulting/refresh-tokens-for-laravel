<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\CustomRefreshToken;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/*
 * The factory names the packaged model in `$model`, so without a `modelName()` override
 * returning the seam it keeps building the packaged class after a host swapped it — and the
 * host's events, observers and casts never run on factory-made tokens.
 */
it('builds the configured model from the factory', function (): void {
    $token = RefreshToken::factory()->forOwner(User::factory()->create())->create();

    expect($token::class)->toBe(CustomRefreshToken::class);
});
