<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\SessionRevoked;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

beforeEach(function (): void {
    $this->spy = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->spy);
});

it('lists only active sessions, newest first', function (): void {
    $user = User::factory()->create();

    RefreshTokenModel::factory()->forUser($user)->create();
    RefreshTokenModel::factory()->forUser($user)->expired()->create();
    RefreshTokenModel::factory()->forUser($user)->revoked()->create();
    $newest = RefreshTokenModel::factory()->forUser($user)->create();

    $sessions = RefreshToken::listFor($user);

    expect($sessions)->toHaveCount(2)
        ->and($sessions->first()->is($newest))->toBeTrue();
});

it('revokes a single session, denies its access reference, and is idempotent', function (): void {
    Event::fake([SessionRevoked::class]);
    $user = User::factory()->create();
    $session = RefreshTokenModel::factory()->forUser($user)->create(['access_reference' => 'acc-x']);

    RefreshToken::revoke($session);
    RefreshToken::revoke($session); // second call must be a no-op

    expect($session->fresh()->revoked_at)->not->toBeNull()
        ->and($session->fresh()->revoked_reason)->toBe(RevocationReason::Manual)
        ->and($this->spy->revoked)->toBe(['acc-x']);

    Event::assertDispatchedTimes(SessionRevoked::class, 1);
});

it('revokeOthers keeps the current session and revokes the rest', function (): void {
    $user = User::factory()->create();
    $current = RefreshTokenModel::factory()->forUser($user)->create(['access_reference' => 'current']);
    RefreshTokenModel::factory()->forUser($user)->create(['access_reference' => 'other-1']);
    RefreshTokenModel::factory()->forUser($user)->create(['access_reference' => 'other-2']);

    $count = RefreshToken::revokeOthers($user, 'current');

    $denied = $this->spy->revoked;
    sort($denied);

    expect($count)->toBe(2)
        ->and($current->fresh()->revoked_at)->toBeNull()
        ->and(RefreshToken::listFor($user))->toHaveCount(1)
        ->and($denied)->toBe(['other-1', 'other-2']);
});

it('revokeAll and revokeAllFor revoke every active session', function (): void {
    $user = User::factory()->create();
    RefreshTokenModel::factory()->count(3)->forUser($user)->create();

    expect(RefreshToken::revokeAll($user))->toBe(3)
        ->and(RefreshToken::listFor($user))->toHaveCount(0);

    RefreshTokenModel::factory()->count(2)->forUser($user)->create();
    expect(RefreshToken::revokeAllFor($user))->toBe(2);
});

it('logs out by plaintext, revoking exactly the matching row', function (): void {
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-logout'));
    RefreshToken::issue($user, new IssueContext); // an unrelated session

    RefreshToken::revoke($new->plainText);

    expect($new->token->fresh()->revoked_at)->not->toBeNull()
        ->and($new->token->fresh()->revoked_reason)->toBe(RevocationReason::Logout)
        ->and($this->spy->revoked)->toBe(['acc-logout'])
        ->and(RefreshToken::listFor($user))->toHaveCount(1);
});

it('ignores logout for an unknown plaintext', function (): void {
    RefreshToken::revoke('never-issued');

    expect($this->spy->revoked)->toBe([]);
});
