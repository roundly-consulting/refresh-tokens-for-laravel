<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

afterEach(fn () => Carbon::setTestNow());

it('prunes rows revoked or expired past the retention window and keeps live ones', function (): void {
    config()->set('refresh-tokens.prune.after', 30);
    $user = User::factory()->create();

    // Long-dead rows (should be pruned).
    Carbon::setTestNow(now()->subDays(60));
    RefreshTokenModel::factory()->forUser($user)->revoked()->create();
    RefreshTokenModel::factory()->forUser($user)->expired()->create();

    // Recent + active rows (should survive).
    Carbon::setTestNow();
    $active = RefreshTokenModel::factory()->forUser($user)->create();
    $recentlyRevoked = RefreshTokenModel::factory()->forUser($user)->revoked()->create();

    $this->artisan('refresh-tokens:prune')
        ->assertSuccessful();

    expect(RefreshTokenModel::withTrashed()->count())->toBe(2)
        ->and(RefreshTokenModel::withTrashed()->whereKey($active->getKey())->exists())->toBeTrue()
        ->and(RefreshTokenModel::withTrashed()->whereKey($recentlyRevoked->getKey())->exists())->toBeTrue();
});

it('honours the --days override', function (): void {
    $user = User::factory()->create();

    Carbon::setTestNow(now()->subDays(10));
    RefreshTokenModel::factory()->forUser($user)->revoked()->create();
    Carbon::setTestNow();

    // Default retention is 30 days: nothing pruned.
    $this->artisan('refresh-tokens:prune')->assertSuccessful();
    expect(RefreshTokenModel::withTrashed()->count())->toBe(1);

    // --days=5 makes the 10-day-old revoked row eligible.
    $this->artisan('refresh-tokens:prune --days=5')->assertSuccessful();
    expect(RefreshTokenModel::withTrashed()->count())->toBe(0);
});

it('force-deletes via the model prunable query (model:prune)', function (): void {
    $user = User::factory()->create();

    Carbon::setTestNow(now()->subDays(90));
    RefreshTokenModel::factory()->forUser($user)->expired()->create();
    Carbon::setTestNow();
    RefreshTokenModel::factory()->forUser($user)->create();

    $this->artisan('model:prune', ['--model' => [RefreshTokenModel::class]])->assertSuccessful();

    expect(RefreshTokenModel::withTrashed()->count())->toBe(1);
});
