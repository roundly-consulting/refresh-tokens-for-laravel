<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

beforeEach(function (): void {
    $this->revoker = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->revoker);
});

afterEach(fn () => Carbon::setTestNow());

it('revokes the whole family and fires the signal when a rotated token is reused', function (): void {
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();

    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    // Present the already-rotated token A again — theft signal.
    expect(RefreshTokens::redeem($a->plainText))->toBeNull();

    // The live replacement B is now revoked as reuse-detected.
    $b = $rotation->newRefreshToken->token->fresh();
    expect($b->revoked_at)->not->toBeNull()
        ->and($b->revoked_reason)->toBe(RevocationReason::ReuseDetected);

    // The host callback denied B's access reference exactly once.
    $this->revoker->assertRevoked('acc-b');
    $this->revoker->assertRevokedCount(1);

    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
    Event::assertDispatched(
        RefreshTokenReuseDetected::class,
        fn (RefreshTokenReuseDetected $e): bool => $e->familyId === $a->token->family_id
            && $e->ownerType === User::class
            && $e->ownerId === $user->id
            && $e->revokedCount === 1,
    );
});

it('does not re-fire the reuse signal when a dead token is replayed', function (): void {
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();

    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    RefreshTokens::redeem($a->plainText); // first reuse: family revoked, one signal
    RefreshTokens::redeem($a->plainText); // replayed dead token: revokes nothing
    RefreshTokens::redeem($a->plainText); // and again

    // Exactly one event and one denial, no matter how often the dead token is replayed.
    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
    $this->revoker->assertRevokedCount(1);
});

it('treats a re-presented token as benign within the grace window', function (): void {
    config()->set('refresh-tokens.rotation.grace', 30);
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();

    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    expect(RefreshTokens::redeem($a->plainText))->toBeNull();

    // Within grace: replacement B untouched, no denial, no event.
    expect($rotation->newRefreshToken->token->fresh()->revoked_at)->toBeNull();
    $this->revoker->assertNothingRevoked();

    Event::assertNotDispatched(RefreshTokenReuseDetected::class);
});

it('stays benign exactly at the grace boundary and turns to reuse just past it', function (): void {
    config()->set('refresh-tokens.rotation.grace', 30);
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();

    // Freeze on a whole second so the stored (second-precision) revoked_at and the
    // in-memory clock agree exactly at the grace boundary.
    Carbon::setTestNow(now()->startOfSecond());
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    // Exactly at the boundary (revoked_at + grace): still benign.
    Carbon::setTestNow(now()->addSeconds(30));
    expect(RefreshTokens::redeem($a->plainText))->toBeNull();
    $this->revoker->assertNothingRevoked();
    Event::assertNotDispatched(RefreshTokenReuseDetected::class);

    // One second past the boundary: reuse.
    Carbon::setTestNow(now()->addSeconds(1));
    expect(RefreshTokens::redeem($a->plainText))->toBeNull();
    $this->revoker->assertRevoked('acc-b');
    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
});
