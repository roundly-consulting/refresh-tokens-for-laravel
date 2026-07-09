<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\SpyAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

beforeEach(function (): void {
    $this->spy = new SpyAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->spy);
});

it('revokes the whole family and fires the signal when a rotated token is reused', function (): void {
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();

    $a = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshToken::rotate($a->plainText, linkedTo: 'acc-b');

    // Present the already-rotated token A again — theft signal.
    expect(RefreshToken::redeem($a->plainText))->toBeNull();

    // The live replacement B is now revoked as reuse-detected.
    $b = $rotation->newRefreshToken->token->fresh();
    expect($b->revoked_at)->not->toBeNull()
        ->and($b->revoked_reason)->toBe(RevocationReason::ReuseDetected);

    // The host callback denied B's access reference exactly once.
    expect($this->spy->revoked)->toBe(['acc-b']);

    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
    Event::assertDispatched(
        RefreshTokenReuseDetected::class,
        fn (RefreshTokenReuseDetected $e): bool => $e->familyId === $a->token->family_id && $e->userId === $user->id,
    );
});

it('treats a re-presented token as benign within the grace window', function (): void {
    config()->set('refresh-tokens.rotation.grace', 30);
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();

    $a = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshToken::rotate($a->plainText, linkedTo: 'acc-b');

    expect(RefreshToken::redeem($a->plainText))->toBeNull();

    // Within grace: replacement B untouched, no denial, no event.
    expect($rotation->newRefreshToken->token->fresh()->revoked_at)->toBeNull()
        ->and($this->spy->revoked)->toBe([]);

    Event::assertNotDispatched(RefreshTokenReuseDetected::class);
});
