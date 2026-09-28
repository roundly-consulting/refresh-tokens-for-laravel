<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Events\SessionRevoked;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/*
 * Logout with the token in hand, when that token was already rotated. The session lives on
 * in the row it was rotated into, so revoking the presented (spent) row alone would leave it
 * running — a thief who rotated a stolen token would outlive the victim's logout. Presenting
 * a spent token is the same theft signal `redeem()` acts on, so outside `rotation.grace`
 * it gets the same response.
 */

beforeEach(function (): void {
    $this->revoker = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->revoker);
});

afterEach(fn () => Carbon::setTestNow());

it('treats a logout with an already-rotated token as reuse and ends the lineage it was rotated into', function (): void {
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();

    $victim = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-victim'));
    $thief = RefreshTokens::rotate($victim->plainText, new RotationContext(accessReference: 'acc-thief'));

    expect(RefreshTokens::revoke($victim->plainText))->toBeTrue()
        ->and($thief?->newRefreshToken->token->fresh()?->revoked_reason)->toBe(RevocationReason::ReuseDetected)
        ->and(RefreshTokens::rotate((string) $thief?->newRefreshToken->plainText))->toBeNull();

    $this->revoker->assertRevoked('acc-thief');
    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
    Event::assertDispatched(
        RefreshTokenReuseDetected::class,
        fn (RefreshTokenReuseDetected $e): bool => $e->familyId === $victim->token->family_id && $e->revokedCount === 1,
    );
});

it('ends the newest row of a longer rotation chain', function (): void {
    $user = User::factory()->create();

    $first = RefreshTokens::issue($user, new IssueContext);
    $second = RefreshTokens::rotate($first->plainText);
    $third = RefreshTokens::rotate((string) $second?->newRefreshToken->plainText);

    expect(RefreshTokens::revoke($first->plainText))->toBeTrue()
        ->and($third?->newRefreshToken->token->fresh()?->isUsable())->toBeFalse()
        ->and(RefreshTokens::sessions($user)->all())->toBeEmpty();
});

it('ends a session caught mid-rotation when its spent token logs out', function (): void {
    Event::fake([SessionRevoked::class]);
    $user = User::factory()->create();

    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $inFlight = RefreshTokens::redeem($a->plainText);

    expect(RefreshTokens::revoke($a->plainText))->toBeTrue()
        ->and($a->token->fresh()?->revoked_reason)->toBe(RevocationReason::ReuseDetected);

    // The in-flight replacement is refused: the logout cannot be outrun by the refresh.
    expect(fn () => RefreshTokens::issue($user, new IssueContext(familyId: $inFlight?->familyId)))
        ->toThrow(InvalidTokenFamilyException::class);

    $this->revoker->assertRevoked('acc-a');
    Event::assertDispatched(SessionRevoked::class, fn (SessionRevoked $e): bool => $e->familyId === $a->token->family_id
        && $e->reason === RevocationReason::ReuseDetected);
});

it('within rotation.grace, ends the lineage with the caller reason and raises no reuse signal', function (): void {
    config()->set('refresh-tokens.rotation.grace', 30);
    Event::fake([RefreshTokenReuseDetected::class, SessionRevoked::class]);
    $user = User::factory()->create();

    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    expect(RefreshTokens::revoke($a->plainText))->toBeTrue()
        ->and($rotation?->newRefreshToken->token->fresh()?->revoked_reason)->toBe(RevocationReason::Logout)
        // The spent row keeps its own story: it was rotated, not logged out.
        ->and($a->token->fresh()?->revoked_reason)->toBe(RevocationReason::Rotated);

    $this->revoker->assertRevoked('acc-b');
    Event::assertNotDispatched(RefreshTokenReuseDetected::class);
    Event::assertDispatched(SessionRevoked::class, fn (SessionRevoked $e): bool => $e->reason === RevocationReason::Logout
        && $e->accessReference === 'acc-b');
});

it('within rotation.grace, seals a session caught mid-rotation with the caller reason', function (): void {
    config()->set('refresh-tokens.rotation.grace', 30);
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();

    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $inFlight = RefreshTokens::redeem($a->plainText);

    expect(RefreshTokens::revoke($a->plainText, RevocationReason::CredentialsChanged))->toBeTrue()
        ->and($a->token->fresh()?->revoked_reason)->toBe(RevocationReason::CredentialsChanged);

    expect(fn () => RefreshTokens::issue($user, new IssueContext(familyId: $inFlight?->familyId)))
        ->toThrow(InvalidTokenFamilyException::class);

    Event::assertNotDispatched(RefreshTokenReuseDetected::class);
});

it('past rotation.grace, a logout with a spent token is reuse again', function (): void {
    config()->set('refresh-tokens.rotation.grace', 30);
    $user = User::factory()->create();

    $a = RefreshTokens::issue($user, new IssueContext);
    $rotation = RefreshTokens::rotate($a->plainText);
    Carbon::setTestNow(now()->addSeconds(31));

    expect(RefreshTokens::revoke($a->plainText))->toBeTrue()
        ->and($rotation?->newRefreshToken->token->fresh()?->revoked_reason)->toBe(RevocationReason::ReuseDetected);
});

it('returns false for a spent token whose session already ended, without a reuse signal', function (): void {
    Event::fake([RefreshTokenReuseDetected::class]);
    $user = User::factory()->create();

    $a = RefreshTokens::issue($user, new IssueContext);
    RefreshTokens::rotate($a->plainText);
    RefreshTokens::sessions($user)->revokeAll();

    expect(RefreshTokens::revoke($a->plainText))->toBeFalse();

    Event::assertNotDispatched(RefreshTokenReuseDetected::class);
});

it('leaves another owner untouched when a spent token logs out', function (): void {
    $user = User::factory()->create();
    $bystander = User::factory()->create();

    $a = RefreshTokens::issue($user, new IssueContext);
    RefreshTokens::rotate($a->plainText);
    $theirs = RefreshTokens::issue($bystander, new IssueContext);

    expect(RefreshTokens::revoke($a->plainText))->toBeTrue()
        ->and($theirs->token->fresh()?->isUsable())->toBeTrue();
});
