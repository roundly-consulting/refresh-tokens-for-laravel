<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenReuseDetected;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

afterEach(fn () => Carbon::setTestNow());

it('prunes rows revoked or expired past the retention window and keeps live ones', function (): void {
    config()->set('refresh-tokens.prune.after', 30);
    $user = User::factory()->create();

    // Long-dead rows (should be pruned).
    Carbon::setTestNow(now()->subDays(60));
    RefreshTokenModel::factory()->forOwner($user)->revoked()->create();
    RefreshTokenModel::factory()->forOwner($user)->expired()->create();

    // Recent + active rows (should survive).
    Carbon::setTestNow();
    $active = RefreshTokenModel::factory()->forOwner($user)->create();
    $recentlyRevoked = RefreshTokenModel::factory()->forOwner($user)->revoked()->create();

    $this->artisan('refresh-tokens:prune')
        ->assertSuccessful();

    expect(RefreshTokenModel::withTrashed()->count())->toBe(2)
        ->and(RefreshTokenModel::withTrashed()->whereKey($active->getKey())->exists())->toBeTrue()
        ->and(RefreshTokenModel::withTrashed()->whereKey($recentlyRevoked->getKey())->exists())->toBeTrue();
});

it('honours the --days override', function (): void {
    $user = User::factory()->create();

    Carbon::setTestNow(now()->subDays(10));
    RefreshTokenModel::factory()->forOwner($user)->revoked()->create();
    Carbon::setTestNow();

    // Default retention is 30 days: nothing pruned.
    $this->artisan('refresh-tokens:prune')->assertSuccessful();
    expect(RefreshTokenModel::withTrashed()->count())->toBe(1);

    // --days=5 makes the 10-day-old revoked row eligible.
    $this->artisan('refresh-tokens:prune --days=5')->assertSuccessful();
    expect(RefreshTokenModel::withTrashed()->count())->toBe(0);
});

it('rejects --days below the one-day floor to preserve reuse evidence', function (): void {
    $user = User::factory()->create();
    Carbon::setTestNow(now()->subHours(2));
    RefreshTokenModel::factory()->forOwner($user)->revoked()->create();
    Carbon::setTestNow();

    $this->artisan('refresh-tokens:prune --days=0')->assertFailed();

    // The recently revoked evidence row was not deleted.
    expect(RefreshTokenModel::withTrashed()->count())->toBe(1);
});

it('rejects a non-numeric --days', function (): void {
    $this->artisan('refresh-tokens:prune --days=abc')->assertFailed();
});

it('floors config-driven retention at one day', function (): void {
    config()->set('refresh-tokens.prune.after', 0);
    $user = User::factory()->create();

    Carbon::setTestNow(now()->subHours(2));
    RefreshTokenModel::factory()->forOwner($user)->revoked()->create();
    Carbon::setTestNow();

    // A retention of 0 would delete the 2-hour-old row; the floor keeps it.
    $this->artisan('refresh-tokens:prune')->assertSuccessful();

    expect(RefreshTokenModel::withTrashed()->count())->toBe(1);
});

it('force-deletes via the model prunable query (model:prune)', function (): void {
    $user = User::factory()->create();

    Carbon::setTestNow(now()->subDays(90));
    RefreshTokenModel::factory()->forOwner($user)->expired()->create();
    Carbon::setTestNow();
    RefreshTokenModel::factory()->forOwner($user)->create();

    $this->artisan('model:prune', ['--model' => [RefreshTokenModel::class]])->assertSuccessful();

    expect(RefreshTokenModel::withTrashed()->count())->toBe(1);
});

/*
 * model:prune reads the window through the model's prunable() query, not through
 * RefreshTokens::prune(). It must honour the same one-day floor: a window of 0 would delete
 * a token rotated a second ago (so a replayed stolen token finds no row and the thief's
 * replacement survives), and a negative one puts the cutoff in the future and deletes live
 * tokens.
 */
it('floors the model:prune retention at one day, keeping reuse evidence and live tokens', function (mixed $configured): void {
    config()->set('refresh-tokens.prune.after', $configured);
    $user = User::factory()->create();

    $stolen = RefreshTokens::issue($user, new IssueContext);
    $thief = RefreshTokens::rotate($stolen->plainText);
    Carbon::setTestNow(now()->addSecond());

    $this->artisan('model:prune', ['--model' => [RefreshTokenModel::class]])->assertSuccessful();

    expect(RefreshTokenModel::withTrashed()->count())->toBe(2);

    // The evidence survived: replaying the stolen token still kills the thief's lineage.
    Event::fake([RefreshTokenReuseDetected::class]);

    expect(RefreshTokens::redeem($stolen->plainText))->toBeNull()
        ->and($thief?->newRefreshToken->token->fresh()?->revoked_reason)->toBe(RevocationReason::ReuseDetected);

    Event::assertDispatchedTimes(RefreshTokenReuseDetected::class, 1);
})->with([
    'zero' => [0],
    'negative' => [-40],
    'numeric string zero' => ['0'],
]);

it('reads a numeric-string retention in model:prune like the command does', function (): void {
    config()->set('refresh-tokens.prune.after', '5');
    $user = User::factory()->create();

    Carbon::setTestNow(now()->subDays(10));
    $old = RefreshTokenModel::factory()->forOwner($user)->revoked()->create();
    Carbon::setTestNow(now()->addDays(7));
    $recent = RefreshTokenModel::factory()->forOwner($user)->revoked()->create();
    Carbon::setTestNow();

    $this->artisan('model:prune', ['--model' => [RefreshTokenModel::class]])->assertSuccessful();

    expect(RefreshTokenModel::withTrashed()->whereKey($old->getKey())->exists())->toBeFalse()
        ->and(RefreshTokenModel::withTrashed()->whereKey($recent->getKey())->exists())->toBeTrue();
});
