<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\AssertionFailedError;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionAttempt;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Enums\RedemptionFailure;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\Client;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/*
 * `RefreshTokens::attempt()` tells a token rotated moments ago, whose session lives on
 * (Superseded), apart from every other failed redeem (Refused) — without weakening reuse
 * detection.
 */
beforeEach(function (): void {
    $this->revoker = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->revoker);
    config()->set('refresh-tokens.rotation.grace', 30);
    Event::fake([RefreshTokenReuseDetected::class]);
});

afterEach(fn () => Carbon::setTestNow());

/**
 * Claim `$row` as a concurrent winner the instant the attempt looks it up.
 */
function claimWhenLookedUp(RefreshTokenModel $row): void
{
    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $row): void {
        if ($raced || ! str_contains($query->sql, 'token_hash')) {
            return;
        }

        $raced = true;

        RefreshTokenModel::query()->whereKey($row->getKey())->update([
            'revoked_at' => now(),
            'revoked_reason' => RevocationReason::Rotated->value,
        ]);
    });
}

it('succeeds like redeem() on a usable token', function (): void {
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext);

    $attempt = RefreshTokens::attempt($new->plainText);

    expect($attempt->succeeded())->toBeTrue()
        ->and($attempt->superseded())->toBeFalse()
        ->and($attempt->failure)->toBe(RedemptionFailure::None)
        ->and($attempt->result?->user->is($user))->toBeTrue()
        ->and($attempt->result?->familyId)->toBe($new->token->family_id);
});

it('reads a concurrent claim lost inside the grace as superseded, revoking nothing', function (): void {
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    // The winner has claimed the row and is still minting the replacement.
    claimWhenLookedUp($new->token);

    $attempt = RefreshTokens::attempt($new->plainText);

    expect($attempt->superseded())->toBeTrue()
        ->and($attempt->result)->toBeNull()
        ->and($new->token->fresh()->revoked_reason)->toBe(RevocationReason::Rotated);

    $this->revoker->assertNothingRevoked();
    Event::assertNotDispatched(RefreshTokenReuseDetected::class);
});

it('reads a concurrent claim lost inside the grace as superseded once the replacement exists', function (): void {
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $replacement = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-b', familyId: $new->token->family_id));

    claimWhenLookedUp($new->token);

    expect(RefreshTokens::attempt($new->plainText)->superseded())->toBeTrue()
        ->and($replacement->token->fresh()->revoked_at)->toBeNull();
});

it('reads a late duplicate inside the grace as superseded', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    $attempt = RefreshTokens::attempt($a->plainText);

    expect($attempt->failure)->toBe(RedemptionFailure::Superseded)
        ->and($rotation?->newRefreshToken->token->fresh()->revoked_at)->toBeNull()
        // The winner's token still redeems.
        ->and(RefreshTokens::attempt($rotation?->newRefreshToken->plainText ?? '')->succeeded())->toBeTrue();

    $this->revoker->assertNothingRevoked();
    Event::assertNotDispatched(RefreshTokenReuseDetected::class);
});

it('refuses a duplicate after the grace as reuse: family revoked and reported', function (): void {
    Carbon::setTestNow(now()->startOfSecond());
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    Carbon::setTestNow(now()->addSeconds(31));

    $attempt = RefreshTokens::attempt($a->plainText);

    expect($attempt->failure)->toBe(RedemptionFailure::Refused)
        ->and($rotation?->newRefreshToken->token->fresh()->revoked_reason)->toBe(RevocationReason::ReuseDetected);

    $this->revoker->assertRevoked('acc-b');
    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
});

it('refuses a concurrent claim lost outside the grace as reuse', function (): void {
    config()->set('refresh-tokens.rotation.grace', 0);
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    claimWhenLookedUp($new->token);

    expect(RefreshTokens::attempt($new->plainText)->failure)->toBe(RedemptionFailure::Refused)
        ->and($new->token->fresh()->revoked_reason)->toBe(RevocationReason::ReuseDetected);

    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
});

it('refuses a token revoked by logout inside the grace, with today\'s side effects', function (RevocationReason $reason): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $other = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-b', familyId: $a->token->family_id));

    RefreshTokenModel::query()->whereKey($a->token->getKey())->update([
        'revoked_at' => now(),
        'revoked_reason' => $reason->value,
    ]);

    // The family still has a usable token, but the presented one was not rotated.
    expect(RefreshTokens::attempt($a->plainText)->failure)->toBe(RedemptionFailure::Refused)
        ->and($other->token->fresh()->revoked_at)->toBeNull();

    Event::assertNotDispatched(RefreshTokenReuseDetected::class);
})->with([
    'logout' => RevocationReason::Logout,
    'logout all' => RevocationReason::LogoutAll,
    'security' => RevocationReason::Security,
    'account disabled' => RevocationReason::AccountDisabled,
    'manual' => RevocationReason::Manual,
]);

it('refuses a rotated token whose session was logged out in the meantime', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    RefreshTokens::revoke($rotation?->newRefreshToken->plainText ?? '');

    expect(RefreshTokens::attempt($a->plainText)->failure)->toBe(RedemptionFailure::Refused);
});

it('refuses a rotated token whose family was revoked in the meantime', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    RefreshTokens::sessions($user)->revokeAll();

    expect(RefreshTokens::attempt($a->plainText)->failure)->toBe(RedemptionFailure::Refused);
});

it('refuses a lost claim whose in-flight rotation was sealed by a logout', function (): void {
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $new, $user): void {
        if ($raced || ! str_contains($query->sql, 'token_hash')) {
            return;
        }

        $raced = true;

        // A winner claims the row, then the owner logs out everywhere mid-rotation.
        RefreshTokenModel::query()->whereKey($new->token->getKey())->update([
            'revoked_at' => now(),
            'revoked_reason' => RevocationReason::Rotated->value,
        ]);
        RefreshTokens::sessions($user)->revokeAll();
    });

    expect(RefreshTokens::attempt($new->plainText)->failure)->toBe(RedemptionFailure::Refused);
});

it('refuses an unknown, an expired and another owner type\'s token alike', function (): void {
    $user = User::factory()->create();
    $live = RefreshTokens::issue($user, new IssueContext);
    $expired = RefreshTokens::issue($user, new IssueContext);
    RefreshTokenModel::query()->whereKey($expired->token->getKey())->update(['expires_at' => now()->subMinute()]);

    $attempts = [
        RefreshTokens::attempt('not-a-token'),
        RefreshTokens::attempt($expired->plainText),
        RefreshTokens::attempt($live->plainText, Client::class),
    ];

    expect(array_map(fn (RedemptionAttempt $attempt): RedemptionFailure => $attempt->failure, $attempts))
        ->toBe([RedemptionFailure::Refused, RedemptionFailure::Refused, RedemptionFailure::Refused])
        ->and(array_map(fn (RedemptionAttempt $attempt): mixed => $attempt->result, $attempts))->toBe([null, null, null])
        // Another owner type's token is not consumed.
        ->and($live->token->fresh()->revoked_at)->toBeNull();
});

it('refuses a superseded token of another owner type without a trace', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext);
    RefreshTokens::rotate($a->plainText);

    expect(RefreshTokens::attempt($a->plainText, Client::class)->failure)->toBe(RedemptionFailure::Refused)
        ->and(RefreshTokens::attempt($a->plainText, User::class)->failure)->toBe(RedemptionFailure::Superseded);
});

it('keeps redeem() returning null for a superseded token', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext);
    $rotation = RefreshTokens::rotate($a->plainText);

    expect(RefreshTokens::redeem($a->plainText))->toBeNull()
        ->and($rotation?->newRefreshToken->token->fresh()->revoked_at)->toBeNull()
        ->and(RefreshTokens::redeem($rotation?->newRefreshToken->plainText ?? ''))->not->toBeNull();
});

it('refuses to build an attempt whose result and failure disagree', function (): void {
    expect(fn () => new RedemptionAttempt(null, RedemptionFailure::None))->toThrow(InvalidArgumentException::class);
});

it('records the outcome in the fake', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext);

    $fake->assertNothingSuperseded();

    RefreshTokens::rotate($a->plainText);
    RefreshTokens::attempt($a->plainText);

    $fake->assertSuperseded();

    $recorded = $fake->recorded();

    expect(fn () => $fake->assertNothingSuperseded())->toThrow(AssertionFailedError::class)
        ->and($recorded[count($recorded) - 1]->failure)->toBe(RedemptionFailure::Superseded);
});
