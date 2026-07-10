<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

afterEach(fn () => Carbon::setTestNow());

it('clamps a rotation replacement to the family absolute ttl', function (): void {
    config()->set('refresh-tokens.ttl', 8_640_000);        // 100 d sliding (root stays usable)
    config()->set('refresh-tokens.absolute_ttl', 3_888_000); // 45 d absolute

    Carbon::setTestNow('2026-01-01 12:00:00');
    $user = User::factory()->create();
    $root = RefreshToken::issue($user, new IssueContext);

    // Rotate 40 days in (root not yet expired): sliding would push expiry to
    // now + 100 d, but the absolute cap holds it at root + 45 d.
    Carbon::setTestNow(now()->addDays(40));
    $rotation = RefreshToken::rotate($root->plainText);

    expect($rotation->newRefreshToken->token->expires_at->toDateTimeString())
        ->toBe('2026-02-15 12:00:00'); // 2026-01-01 + 45 days
});

it('uses the sliding ttl when it is shorter than the absolute cap', function (): void {
    config()->set('refresh-tokens.ttl', 2_592_000);        // 30 d
    config()->set('refresh-tokens.absolute_ttl', 7_776_000); // 90 d

    Carbon::setTestNow('2026-01-01 12:00:00');
    $user = User::factory()->create();
    $root = RefreshToken::issue($user, new IssueContext);

    // Rotate one day in: sliding (day 1 + 30 d) is well under the 90 d absolute cap.
    Carbon::setTestNow(now()->addDay());
    $rotation = RefreshToken::rotate($root->plainText);

    expect($rotation->newRefreshToken->token->expires_at->toDateTimeString())
        ->toBe('2026-02-01 12:00:00'); // 2026-01-02 + 30 days
});

it('does not cap expiry when the absolute ttl is disabled', function (): void {
    config()->set('refresh-tokens.ttl', 2_592_000);
    config()->set('refresh-tokens.absolute_ttl', 0);

    Carbon::setTestNow('2026-01-01 12:00:00');
    $user = User::factory()->create();
    $root = RefreshToken::issue($user, new IssueContext);

    // Rotate 10 days in (root still usable): full sliding TTL from the rotation
    // instant, no clamp.
    Carbon::setTestNow(now()->addDays(10));
    $expected = CarbonImmutable::now()->addSeconds(2_592_000)->toDateTimeString();
    $rotation = RefreshToken::rotate($root->plainText);

    expect($rotation->newRefreshToken->token->expires_at->toDateTimeString())->toBe($expected);
});

it('does not clamp a fresh (family-rooting) token', function (): void {
    config()->set('refresh-tokens.ttl', 2_592_000);
    config()->set('refresh-tokens.absolute_ttl', 3_888_000);

    Carbon::setTestNow('2026-01-01 12:00:00');
    $user = User::factory()->create();
    $root = RefreshToken::issue($user, new IssueContext);

    // A brand-new root gets the full sliding TTL; the cap only applies on rotation.
    expect($root->token->expires_at->toDateTimeString())->toBe('2026-01-31 12:00:00');
});
