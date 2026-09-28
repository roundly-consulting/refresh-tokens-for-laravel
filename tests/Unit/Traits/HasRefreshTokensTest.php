<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\Client;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

it('exposes the refreshTokens relation through the polymorphic owner', function (): void {
    $user = User::factory()->create();
    RefreshToken::factory()->forOwner($user)->count(2)->create();
    RefreshToken::factory()->forOwner(User::factory()->create())->create();

    expect($user->refreshTokens()->count())->toBe(2);
});

it('exposes only active tokens as sessions', function (): void {
    $user = User::factory()->create();
    RefreshToken::factory()->forOwner($user)->create();
    RefreshToken::factory()->forOwner($user)->expired()->create();
    RefreshToken::factory()->forOwner($user)->revoked()->create();

    expect($user->sessions()->count())->toBe(1);
});

it('issues a refresh token through the trait verb', function (): void {
    $user = User::factory()->create();

    $new = $user->issueRefreshToken(new IssueContext(accessReference: 'acc-1'));

    expect($new)->toBeInstanceOf(NewRefreshToken::class)
        ->and($new->token->owner_id)->toBe($user->id)
        ->and($new->token->owner_type)->toBe(User::class)
        ->and($new->token->access_reference)->toBe('acc-1');
});

it('revokeAllSessions revokes every active session like sessions()->revokeAll', function (): void {
    $this->app->instance(AccessTokenRevoker::class, new FakeAccessTokenRevoker);
    $user = User::factory()->create();
    RefreshToken::factory()->forOwner($user)->count(3)->create();

    expect($user->revokeAllSessions())->toBe(3)
        ->and($user->sessions()->count())->toBe(0);
});

it('revokeOtherSessions keeps the current session and revokes the rest', function (): void {
    $this->app->instance(AccessTokenRevoker::class, new FakeAccessTokenRevoker);
    $user = User::factory()->create();
    $current = RefreshToken::factory()->forOwner($user)->create(['access_reference' => 'current']);
    RefreshToken::factory()->forOwner($user)->count(2)->create();

    expect($user->revokeOtherSessions('current'))->toBe(2)
        ->and($current->fresh()->revoked_at)->toBeNull()
        ->and($user->sessions()->count())->toBe(1);
});

it('scopes the relation to the owner type when ids collide', function (): void {
    $user = User::factory()->create();
    $client = Client::factory()->create();
    RefreshToken::factory()->forOwner($user)->create();
    RefreshToken::factory()->forOwner($client)->count(2)->create();

    expect($user->refreshTokens()->count())->toBe(1)
        ->and($client->refreshTokens()->count())->toBe(2);
});
