<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenIssued;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

it('issues a token storing only the hash and returns the plaintext once', function (): void {
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext(
        ipAddress: '203.0.113.9',
        userAgent: 'PestBrowser/1.0',
        accessReference: 'acc-ref-1',
    ));

    expect($new)->toBeInstanceOf(NewRefreshToken::class)
        ->and($new->plainText)->toHaveLength(64);

    $row = $new->token;
    expect($row->token_hash)->toBe(hash('sha256', $new->plainText))
        ->and($row->token_hash)->not->toBe($new->plainText)
        ->and($row->user_id)->toBe($user->id)
        ->and($row->access_reference)->toBe('acc-ref-1')
        ->and($row->ip_address)->toBe('203.0.113.9')
        ->and($row->user_agent)->toBe('PestBrowser/1.0')
        ->and($row->family_id)->not->toBeNull()
        ->and($row->revoked_at)->toBeNull()
        ->and($row->expires_at->isFuture())->toBeTrue();
});

it('roots a new family when none is provided and inherits when one is', function (): void {
    $user = User::factory()->create();

    $first = RefreshToken::issue($user, new IssueContext);
    $inherited = RefreshToken::issue($user, new IssueContext(familyId: $first->token->family_id));
    $fresh = RefreshToken::issue($user, new IssueContext);

    expect($inherited->token->family_id)->toBe($first->token->family_id)
        ->and($fresh->token->family_id)->not->toBe($first->token->family_id);
});

it('honours the configured ttl', function (): void {
    config()->set('refresh-tokens.ttl', 3600);
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext);

    expect($new->token->expires_at->timestamp - now()->timestamp)->toEqualWithDelta(3600, 5);
});

it('fires RefreshTokenIssued with the row id', function (): void {
    Event::fake();
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext);

    Event::assertDispatched(RefreshTokenIssued::class, fn (RefreshTokenIssued $e): bool => $e->tokenId === $new->token->getKey());
});

it('issues through the fluent builder from a request', function (): void {
    $user = User::factory()->create();

    $new = RefreshToken::for($user)
        ->withIp('198.51.100.5')
        ->withUserAgent('Fluent/2.0')
        ->linkedTo('acc-ref-fluent')
        ->issue();

    $row = RefreshTokenModel::query()->firstOrFail();
    expect($row->ip_address)->toBe('198.51.100.5')
        ->and($row->user_agent)->toBe('Fluent/2.0')
        ->and($row->access_reference)->toBe('acc-ref-fluent')
        ->and($new->token->is($row))->toBeTrue();
});
