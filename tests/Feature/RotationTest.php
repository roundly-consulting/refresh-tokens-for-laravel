<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenIssued;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenRedeemed;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

afterEach(fn () => Carbon::setTestNow());

it('redeems a valid token, returning the user and revoking the row as rotated', function (): void {
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext);

    $result = RefreshToken::redeem($new->plainText);

    expect($result)->toBeInstanceOf(RedemptionResult::class)
        ->and($result->user->getAuthIdentifier())->toBe($user->id)
        ->and($result->familyId)->toBe($new->token->family_id);

    $row = $new->token->fresh();
    expect($row->revoked_at)->not->toBeNull()
        ->and($row->revoked_reason)->toBe(RevocationReason::Rotated);
});

it('returns null on a second redeem of the same token', function (): void {
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext);

    RefreshToken::redeem($new->plainText);

    expect(RefreshToken::redeem($new->plainText))->toBeNull();
});

it('returns null for an unknown token', function (): void {
    expect(RefreshToken::redeem('this-token-was-never-issued'))->toBeNull();
});

it('returns null for an expired token without revoking the family', function (): void {
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-1'));

    Carbon::setTestNow(now()->addYear());

    expect(RefreshToken::redeem($new->plainText))->toBeNull();

    // Expired-only presentation is not a reuse signal.
    expect($new->token->fresh()->revoked_reason)->toBeNull();
});

it('rotates: redeem then issue a same-family replacement in one call', function (): void {
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext);

    $rotation = RefreshToken::rotate($new->plainText, new RotationContext(accessReference: 'acc-new'));

    expect($rotation)->toBeInstanceOf(RotationResult::class)
        ->and($rotation->redeemedFamilyId)->toBe($new->token->family_id)
        ->and($rotation->newRefreshToken->token->family_id)->toBe($new->token->family_id)
        ->and($rotation->newRefreshToken->token->access_reference)->toBe('acc-new')
        ->and($rotation->newRefreshToken->plainText)->not->toBe($new->plainText);

    expect($new->token->fresh()->revoked_at)->not->toBeNull();
});

it('returns null from rotate when the redeem fails', function (): void {
    expect(RefreshToken::rotate('unknown-token'))->toBeNull();
});

it('fires RefreshTokenRedeemed exactly once on a successful redeem', function (): void {
    Event::fake([RefreshTokenRedeemed::class]);
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext);

    RefreshToken::redeem($new->plainText);

    Event::assertDispatchedTimes(RefreshTokenRedeemed::class, 1);
    Event::assertDispatched(
        RefreshTokenRedeemed::class,
        fn (RefreshTokenRedeemed $e): bool => $e->tokenId === $new->token->getKey()
            && $e->familyId === $new->token->family_id
            && $e->ownerType === User::class
            && $e->ownerId === $user->id,
    );
});

it('does not fire RefreshTokenRedeemed on unknown, expired or second-redeem paths', function (): void {
    Event::fake([RefreshTokenRedeemed::class]);
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext);

    RefreshToken::redeem('never-issued');           // unknown
    RefreshToken::redeem($new->plainText);           // success (one event)
    RefreshToken::redeem($new->plainText);           // second redeem → null

    Carbon::setTestNow(now()->addYear());
    $expired = RefreshToken::issue($user, new IssueContext);
    Carbon::setTestNow(now()->addYears(2));
    RefreshToken::redeem($expired->plainText);       // expired → null

    Event::assertDispatchedTimes(RefreshTokenRedeemed::class, 1);
});

it('claims the row but returns null and emits no success when the owner is gone', function (): void {
    Event::fake([RefreshTokenRedeemed::class]);
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext);

    // Owner deleted after issue: the row is still claimed/revoked, but redeem yields null.
    $user->delete();

    expect(RefreshToken::redeem($new->plainText))->toBeNull()
        ->and($new->token->fresh()->revoked_at)->not->toBeNull()
        ->and($new->token->fresh()->revoked_reason)->toBe(RevocationReason::Rotated);

    Event::assertNotDispatched(RefreshTokenRedeemed::class);
});

it('rotate fires one RefreshTokenRedeemed and one RefreshTokenIssued', function (): void {
    Event::fake([RefreshTokenRedeemed::class, RefreshTokenIssued::class]);
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext); // one issued (for the original)

    RefreshToken::rotate($new->plainText, new RotationContext(accessReference: 'acc-new'));

    // The redeem of the old token, plus the issue of the replacement.
    Event::assertDispatchedTimes(RefreshTokenRedeemed::class, 1);
    Event::assertDispatchedTimes(RefreshTokenIssued::class, 2);
});

/*
 * Inheritance — asserted for BOTH refresh paths:
 *
 *  - `rotate()`: redeem + issue in one call;
 *  - `redeem()` then `issue(familyId: …)`: the path a host takes when the replacement's
 *    access reference is minted AFTER the redeem. At that issue the family has NO active
 *    row (redeem just claimed it), so inheriting from "the active row" would silently drop
 *    everything. The source is the family's newest row, revoked or not.
 */
dataset('refresh paths', [
    'rotate()' => [
        fn (string $plain, ?string $ip, ?string $ua, ?array $meta): ?NewRefreshToken => RefreshToken::rotate(
            $plain,
            new RotationContext(ipAddress: $ip, userAgent: $ua, accessReference: 'acc-next', meta: $meta),
        )?->newRefreshToken,
    ],
    'redeem() + issue(familyId)' => [
        function (string $plain, ?string $ip, ?string $ua, ?array $meta): ?NewRefreshToken {
            $redeemed = RefreshToken::redeem($plain);

            return $redeemed === null ? null : RefreshToken::issue($redeemed->user, new IssueContext(
                ipAddress: $ip,
                userAgent: $ua,
                accessReference: 'acc-next',
                familyId: $redeemed->familyId,
                meta: $meta,
            ));
        },
    ],
]);

function enrichedRoot(User $user): NewRefreshToken
{
    $root = RefreshToken::issue($user, new IssueContext(
        ipAddress: '198.51.100.1',
        userAgent: 'Root/1.0',
        meta: ['guard' => 'users', 'amr' => ['pwd'], 'auth_time' => 1_767_268_800],
    ));

    RefreshToken::enrich(
        $root->token,
        new DeviceData(browser: 'Firefox', browserVersion: '130', os: 'Linux', osVersion: '6', deviceType: DeviceType::Desktop, isBot: false),
        new LocationData(country: 'Slovakia', city: 'Bratislava', countryCode: 'SK', ipAddress: '198.51.100.1'),
    );

    return $root;
}

it('inherits meta, merging the new keys over the old', function (Closure $refresh): void {
    $user = User::factory()->create();
    $root = enrichedRoot($user);

    $next = $refresh($root->plainText, null, null, ['auth_time' => 1_767_300_000, 'device_name' => 'Laptop']);

    // toEqual, not toBe: Postgres `jsonb` does not preserve object key order.
    expect($next?->token->fresh()->meta)->toEqual([
        'guard' => 'users',
        'amr' => ['pwd'],
        'auth_time' => 1_767_300_000,
        'device_name' => 'Laptop',
    ]);
})->with('refresh paths');

it('inherits meta unchanged when none is given', function (Closure $refresh): void {
    $root = enrichedRoot(User::factory()->create());

    $next = $refresh($root->plainText, null, null, null);

    expect($next?->token->fresh()->meta)->toEqual(['guard' => 'users', 'amr' => ['pwd'], 'auth_time' => 1_767_268_800]);
})->with('refresh paths');

it('carries the device and geo columns forward', function (Closure $refresh): void {
    $root = enrichedRoot(User::factory()->create());

    $row = $refresh($root->plainText, null, null, null)?->token->fresh();

    expect($row?->browser)->toBe('Firefox')
        ->and($row?->browser_version)->toBe('130')
        ->and($row?->os)->toBe('Linux')
        ->and($row?->os_version)->toBe('6')
        ->and($row?->device_type)->toBe(DeviceType::Desktop)
        ->and($row?->is_bot)->toBeFalse()
        ->and($row?->country)->toBe('Slovakia')
        ->and($row?->city)->toBe('Bratislava')
        ->and($row?->country_code)->toBe('SK')
        // No new ip/ua given: the previous ones are kept.
        ->and($row?->ip_address)->toBe('198.51.100.1')
        ->and($row?->user_agent)->toBe('Root/1.0')
        ->and($row?->access_reference)->toBe('acc-next');
})->with('refresh paths');

it('records the current ip and user agent when given', function (Closure $refresh): void {
    $root = enrichedRoot(User::factory()->create());

    $row = $refresh($root->plainText, '203.0.113.50', 'Next/2.0', null)?->token->fresh();

    expect($row?->ip_address)->toBe('203.0.113.50')
        ->and($row?->user_agent)->toBe('Next/2.0')
        ->and($row?->browser)->toBe('Firefox');
})->with('refresh paths');

it('keeps the family timestamps identical across consecutive rotations', function (Closure $refresh): void {
    config()->set('refresh-tokens.absolute_ttl', 3_888_000);
    Carbon::setTestNow('2026-01-01 12:00:00');
    $root = enrichedRoot(User::factory()->create());
    $first = $root->token->fresh();

    $plain = $root->plainText;
    $rows = [];

    foreach ([1, 2, 3] as $day) {
        Carbon::setTestNow(Carbon::parse('2026-01-01 12:00:00')->addDays($day));
        $next = $refresh($plain, null, null, null);
        expect($next)->not->toBeNull();
        $plain = (string) $next?->plainText;
        $rows[] = $next?->token->fresh();
    }

    foreach ($rows as $row) {
        expect($row?->family_id)->toBe($first->family_id)
            ->and($row?->family_started_at?->toDateTimeString())->toBe('2026-01-01 12:00:00')
            ->and($row?->absolute_expires_at?->toDateTimeString())->toBe('2026-02-15 12:00:00')
            ->and($row?->sessionStartedAt()->toDateTimeString())->toBe('2026-01-01 12:00:00')
            ->and($row?->meta)->toBe($first->meta);
    }
})->with('refresh paths');

it('applies a rotation ttl to the replacement', function (): void {
    $user = User::factory()->create();
    $root = RefreshToken::issue($user, new IssueContext);

    $rotation = RefreshToken::rotate($root->plainText, new RotationContext(ttl: 300));

    expect($rotation?->newRefreshToken->token->expires_at->timestamp - now()->timestamp)->toEqualWithDelta(300, 5);
});

it('inherits from the newest family row, not an older one', function (): void {
    $user = User::factory()->create();
    Carbon::setTestNow('2026-01-01 12:00:00');
    $root = RefreshToken::issue($user, new IssueContext(meta: ['v' => 1]));

    Carbon::setTestNow('2026-01-02 12:00:00');
    $second = RefreshToken::rotate($root->plainText, new RotationContext(meta: ['v' => 2]));

    Carbon::setTestNow('2026-01-03 12:00:00');
    $explicit = RefreshToken::issue($user, new IssueContext(familyId: $root->token->family_id));

    expect($second?->newRefreshToken->token->fresh()->meta)->toBe(['v' => 2])
        ->and($explicit->token->fresh()->meta)->toBe(['v' => 2]);
});
