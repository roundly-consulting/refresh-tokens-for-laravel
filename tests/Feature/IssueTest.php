<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenIssued;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

it('issues a token storing only the hash and returns the plaintext once', function (): void {
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext(
        ipAddress: '203.0.113.9',
        userAgent: 'PestBrowser/1.0',
        accessReference: 'acc-ref-1',
    ));

    expect($new)->toBeInstanceOf(NewRefreshToken::class)
        ->and($new->plainText)->toHaveLength(64);

    $row = $new->token;
    expect($row->token_hash)->toBe(hash('sha256', $new->plainText))
        ->and($row->token_hash)->not->toBe($new->plainText)
        ->and($row->owner_type)->toBe($user->getMorphClass())
        ->and($row->owner_id)->toBe($user->id)
        ->and($row->access_reference)->toBe('acc-ref-1')
        ->and($row->ip_address)->toBe('203.0.113.9')
        ->and($row->user_agent)->toBe('PestBrowser/1.0')
        ->and($row->family_id)->not->toBeNull()
        ->and($row->revoked_at)->toBeNull()
        ->and($row->expires_at->isFuture())->toBeTrue();
});

it('roots a new family when none is provided and inherits when one is', function (): void {
    $user = User::factory()->create();

    $first = RefreshToken::issue($user, new IssueContext);
    $inherited = RefreshToken::issue($user, new IssueContext(familyId: $first->token->family_id));
    $fresh = RefreshToken::issue($user, new IssueContext);

    expect($inherited->token->family_id)->toBe($first->token->family_id)
        ->and($fresh->token->family_id)->not->toBe($first->token->family_id);
});

it('honours the configured ttl', function (): void {
    config()->set('refresh-tokens.ttl', 3600);
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext);

    expect($new->token->expires_at->timestamp - now()->timestamp)->toEqualWithDelta(3600, 5);
});

it('fires RefreshTokenIssued with the row, family and owner', function (): void {
    Event::fake();
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext);

    Event::assertDispatched(
        RefreshTokenIssued::class,
        fn (RefreshTokenIssued $e): bool => $e->tokenId === $new->token->getKey()
            && $e->familyId === $new->token->family_id
            && $e->ownerType === User::class
            && $e->ownerId === $user->id,
    );
});

it('issues through the fluent builder from a request', function (): void {
    $user = User::factory()->create();

    $new = RefreshToken::for($user)
        ->withIp('198.51.100.5')
        ->withUserAgent('Fluent/2.0')
        ->linkedTo('acc-ref-fluent')
        ->issue();

    $row = RefreshTokenModel::query()->firstOrFail();
    expect($row->ip_address)->toBe('198.51.100.5')
        ->and($row->user_agent)->toBe('Fluent/2.0')
        ->and($row->access_reference)->toBe('acc-ref-fluent')
        ->and($new->token->is($row))->toBeTrue();
});

it('roots a new family under a caller-chosen uuid', function (): void {
    Event::fake([RefreshTokenIssued::class]);
    $user = User::factory()->create();
    $sid = (string) Str::uuid();

    $new = RefreshToken::issue($user, new IssueContext(newFamilyId: $sid));

    expect($new->token->family_id)->toBe($sid)
        ->and($new->token->family_started_at)->not->toBeNull()
        ->and(RefreshToken::findSession($user, $sid)?->is($new->token))->toBeTrue();

    Event::assertDispatched(RefreshTokenIssued::class, fn (RefreshTokenIssued $e): bool => $e->familyId === $sid);
});

/**
 * A malformed root id is rejected before ANY query: `family_id` is a uuid column and
 * Postgres would otherwise answer with a raw QueryException (the 2f3aebc bug class).
 * Counting queries proves the ordering on every driver, including the pgsql leg.
 */
it('rejects a malformed newFamilyId before touching the database', function (string $familyId): void {
    $user = User::factory()->create();
    $queries = 0;
    DB::listen(function (QueryExecuted $query) use (&$queries): void {
        $queries++;
    });

    expect(fn () => RefreshToken::issue($user, new IssueContext(newFamilyId: $familyId)))
        ->toThrow(InvalidTokenFamilyException::class, 'is not a valid UUID');

    expect($queries)->toBe(0);
})->with([
    'not a uuid' => 'session-1',
    'empty' => '',
    'truncated' => '11111111-2222-3333-4444-55555555555',
]);

it('rejects a newFamilyId that already names a family, of any owner', function (): void {
    $user = User::factory()->create();
    $other = User::factory()->create();
    $existing = RefreshToken::issue($other, new IssueContext);

    expect(fn () => RefreshToken::issue($user, new IssueContext(newFamilyId: $existing->token->family_id)))
        ->toThrow(InvalidTokenFamilyException::class, 'already exists');
});

/*
 * Family ids are uuids, and a uuid is case-insensitive: Postgres' uuid column says so
 * (it stores and compares them canonically, lowercase), sqlite/mysql text columns
 * would not. The package canonicalises them, so every driver answers alike.
 */
it('treats family ids case-insensitively on every driver', function (): void {
    $user = User::factory()->create();
    $sid = (string) Str::uuid();

    $root = RefreshToken::issue($user, new IssueContext(newFamilyId: strtoupper($sid)));

    expect($root->token->family_id)->toBe($sid)
        ->and($root->token->fresh()->family_id)->toBe($sid)
        ->and(RefreshToken::findSession($user, strtoupper($sid))?->is($root->token))->toBeTrue()
        ->and(fn () => RefreshToken::issue($user, new IssueContext(newFamilyId: strtoupper($sid))))
        ->toThrow(InvalidTokenFamilyException::class, 'already exists');

    $child = RefreshToken::issue($user, new IssueContext(familyId: strtoupper($sid)));

    expect($child->token->family_id)->toBe($sid)
        ->and(RefreshToken::revokeSession($user, strtoupper($sid)))->toBeTrue()
        ->and(RefreshToken::listFor($user))->toBeEmpty();
});

it('rejects familyId and newFamilyId together', function (): void {
    $user = User::factory()->create();
    $existing = RefreshToken::issue($user, new IssueContext);

    expect(fn () => RefreshToken::issue($user, new IssueContext(
        familyId: $existing->token->family_id,
        newFamilyId: (string) Str::uuid(),
    )))->toThrow(InvalidTokenFamilyException::class, 'not both');
});

it('honours a per-issue ttl over the configured one', function (): void {
    config()->set('refresh-tokens.ttl', 3600);
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext(ttl: 120));

    expect($new->token->expires_at->timestamp - now()->timestamp)->toEqualWithDelta(120, 5);
});

it('rejects an out-of-range per-issue lifetime', function (IssueContext $context, string $message): void {
    $user = User::factory()->create();

    expect(fn () => RefreshToken::issue($user, $context))
        ->toThrow(InvalidTokenConfigurationException::class, $message);
})->with([
    'zero ttl' => [new IssueContext(ttl: 0), 'ttl [0]'],
    'negative ttl' => [new IssueContext(ttl: -5), 'ttl [-5]'],
    'negative absolute ttl' => [new IssueContext(absoluteTtl: -1), 'absoluteTtl [-1]'],
]);

it('stores session meta at issue', function (): void {
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext(meta: ['guard' => 'users', 'amr' => ['pwd', 'otp']]));

    // toEqual, not toBe: Postgres `jsonb` does not preserve object key order (list order is kept).
    expect($new->token->fresh()->meta)->toEqual(['guard' => 'users', 'amr' => ['pwd', 'otp']])
        ->and(RefreshToken::issue($user, new IssueContext(meta: []))->token->fresh()->meta)->toBeNull();
});

it('carries every new option through the fluent builder', function (): void {
    config()->set('refresh-tokens.absolute_ttl', 0);
    $user = User::factory()->create();
    $sid = (string) Str::uuid();

    $new = RefreshToken::for($user)
        ->startingFamily($sid)
        ->ttl(600)
        ->absoluteTtl(3600)
        ->meta(['device_name' => 'Pixel'])
        ->issue();

    $row = $new->token->fresh();

    expect($row->family_id)->toBe($sid)
        ->and($row->expires_at->timestamp - now()->timestamp)->toEqualWithDelta(600, 5)
        ->and($row->absolute_expires_at?->timestamp - now()->timestamp)->toEqualWithDelta(3600, 5)
        ->and($row->meta)->toBe(['device_name' => 'Pixel']);
});
