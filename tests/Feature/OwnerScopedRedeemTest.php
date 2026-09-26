<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenRedeemed;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\Client;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/**
 * A guard-scoped refresh endpoint passes its owner type. A token of another type is
 * UNKNOWN to it: not claimed, no family revoke, no event — presenting a user's token at
 * the clients endpoint must neither burn the user's session nor count as reuse.
 */
beforeEach(function (): void {
    $this->revoker = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->revoker);
});

it('treats a foreign owner type as unknown and leaves the token usable', function (): void {
    Event::fake([RefreshTokenRedeemed::class, RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-u'));

    expect(RefreshToken::redeem($new->plainText, Client::class))->toBeNull();

    $row = $new->token->fresh();
    expect($row->revoked_at)->toBeNull()
        ->and($row->revoked_reason)->toBeNull()
        ->and($row->isUsable())->toBeTrue();

    $this->revoker->assertNothingRevoked();
    Event::assertNotDispatched(RefreshTokenRedeemed::class);
    Event::assertNotDispatched(RefreshTokenReuseDetected::class);

    // Then the right endpoint redeems it normally.
    $result = RefreshToken::redeem($new->plainText, User::class);

    expect($result)->not->toBeNull()
        ->and($result?->user->is($user))->toBeTrue();
    Event::assertDispatchedTimes(RefreshTokenRedeemed::class, 1);
});

it('does not treat a rotated token presented at a foreign endpoint as reuse', function (): void {
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();
    $a = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshToken::rotate($a->plainText, new RotationContext(ownerType: User::class, accessReference: 'acc-b'));

    // The rotated (dead) token shown at the clients endpoint: invisible, so no family kill.
    expect(RefreshToken::redeem($a->plainText, Client::class))->toBeNull()
        ->and($rotation?->newRefreshToken->token->fresh()->revoked_at)->toBeNull();

    $this->revoker->assertNothingRevoked();
    Event::assertNotDispatched(RefreshTokenReuseDetected::class);

    // At its own endpoint the same presentation IS reuse.
    expect(RefreshToken::redeem($a->plainText, User::class))->toBeNull();
    $this->revoker->assertRevoked('acc-b');
    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
});

it('scopes a one-call rotation to the owner type', function (): void {
    $client = Client::factory()->create();
    $new = RefreshToken::issue($client, new IssueContext);

    expect(RefreshToken::rotate($new->plainText, new RotationContext(ownerType: User::class)))->toBeNull()
        ->and($new->token->fresh()->revoked_at)->toBeNull();

    $rotation = RefreshToken::rotate($new->plainText, new RotationContext(ownerType: Client::class));

    expect($rotation)->not->toBeNull()
        ->and($rotation?->user)->toBeInstanceOf(Client::class)
        ->and($rotation?->newRefreshToken->token->owner_type)->toBe(Client::class);
});

it('redeems any owner type when no scope is given', function (): void {
    $client = Client::factory()->create();
    $new = RefreshToken::issue($client, new IssueContext);

    expect(RefreshToken::redeem($new->plainText)?->user)->toBeInstanceOf(Client::class);
});
