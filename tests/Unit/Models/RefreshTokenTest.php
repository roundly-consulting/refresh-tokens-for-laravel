<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

afterEach(fn () => Carbon::setTestNow());

it('reports usability correctly across edges', function (): void {
    expect(RefreshToken::factory()->make()->isUsable())->toBeTrue()
        ->and(RefreshToken::factory()->expired()->make()->isUsable())->toBeFalse()
        ->and(RefreshToken::factory()->revoked()->make()->isUsable())->toBeFalse();
});

it('treats a token expiring exactly now as not usable', function (): void {
    Carbon::setTestNow('2026-07-09 20:00:00');
    $token = RefreshToken::factory()->make(['expires_at' => now()]);

    expect($token->isUsable())->toBeFalse();
});

it('casts columns to their rich types', function (): void {
    $user = User::factory()->create();
    $token = RefreshToken::factory()->forUser($user)->create([
        'device_type' => DeviceType::Mobile,
        'revoked_reason' => RevocationReason::Rotated,
        'is_bot' => true,
    ]);

    $fresh = $token->fresh();
    expect($fresh->device_type)->toBe(DeviceType::Mobile)
        ->and($fresh->revoked_reason)->toBe(RevocationReason::Rotated)
        ->and($fresh->is_bot)->toBeTrue()
        ->and($fresh->expires_at)->toBeInstanceOf(CarbonImmutable::class);
});

it('scopes active, expired and family rows', function (): void {
    $user = User::factory()->create();
    $active = RefreshToken::factory()->forUser($user)->create();
    $expired = RefreshToken::factory()->forUser($user)->expired()->create();
    $revoked = RefreshToken::factory()->forUser($user)->revoked()->create();
    // A real uuid, not 'fam-1': `family_id` is a uuid column, so a strict engine rejects
    // the comparison outright. The old literal only worked because sqlite compares uuid
    // columns as text.
    $familyId = (string) Str::uuid();
    $family = RefreshToken::factory()->forUser($user)->forFamily($familyId)->create();

    expect(RefreshToken::query()->active()->pluck('id')->all())->toBe([$active->id, $family->id])
        ->and(RefreshToken::query()->expired()->pluck('id')->all())->toContain($expired->id)
        ->and(RefreshToken::query()->forFamily($familyId)->pluck('id')->all())->toBe([$family->id])
        ->and($revoked->isUsable())->toBeFalse();
});

it('resolves the owner relation against the configured user model', function (): void {
    $user = User::factory()->create();
    $token = RefreshToken::factory()->forUser($user)->create();

    expect($token->owner->is($user))->toBeTrue();
});

it('honours a custom table name from config', function (): void {
    config()->set('refresh-tokens.table', 'custom_tokens');

    expect((new RefreshToken)->getTable())->toBe('custom_tokens');
});

it('hides the digest and access reference from array and json output', function (): void {
    $user = User::factory()->create();
    $token = RefreshToken::factory()->forUser($user)->create(['access_reference' => 'jti-secret']);

    $array = $token->toArray();
    expect($array)->not->toHaveKey('token_hash')
        ->and($array)->not->toHaveKey('access_reference');

    $json = $token->toJson();
    expect($json)->not->toContain('token_hash')
        ->and($json)->not->toContain($token->token_hash)
        ->and($json)->not->toContain('jti-secret');
});

it('selects prunable rows revoked or expired past the window', function (): void {
    config()->set('refresh-tokens.prune.after', 30);
    $user = User::factory()->create();

    Carbon::setTestNow(now()->subDays(60));
    $old = RefreshToken::factory()->forUser($user)->revoked()->create();
    Carbon::setTestNow();
    $live = RefreshToken::factory()->forUser($user)->create();

    $ids = (new RefreshToken)->prunable()->pluck('id')->all();

    expect($ids)->toContain($old->id)->not->toContain($live->id);
});
