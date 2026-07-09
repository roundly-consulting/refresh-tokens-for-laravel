<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
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

it('issues a refresh token through the trait verb', function (): void {
    $user = User::factory()->create();

    $new = $user->issueRefreshToken(new IssueContext(accessReference: 'acc-1'));

    expect($new)->toBeInstanceOf(NewRefreshToken::class)
        ->and($new->token->getAttribute('user_id'))->toBe($user->id)
        ->and($new->token->access_reference)->toBe('acc-1');
});

it('revokeAllSessions revokes every active session like revokeAllFor', function (): void {
    $this->app->instance(AccessTokenRevoker::class, new FakeAccessTokenRevoker);
    $user = User::factory()->create();
    RefreshToken::factory()->forUser($user)->count(3)->create();

    expect($user->revokeAllSessions())->toBe(3)
        ->and($user->sessions()->count())->toBe(0);
});

it('revokeOtherSessions keeps the current session and revokes the rest', function (): void {
    $this->app->instance(AccessTokenRevoker::class, new FakeAccessTokenRevoker);
    $user = User::factory()->create();
    $current = RefreshToken::factory()->forUser($user)->create(['access_reference' => 'current']);
    RefreshToken::factory()->forUser($user)->count(2)->create();

    expect($user->revokeOtherSessions('current'))->toBe(2)
        ->and($current->fresh()->revoked_at)->toBeNull()
        ->and($user->sessions()->count())->toBe(1);
});
