<?php

declare(strict_types=1);

use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

beforeEach(function (): void {
    $this->app->instance(AccessTokenRevoker::class, new FakeAccessTokenRevoker);
});

it('rejects issuing into a family that does not exist', function (): void {
    $user = User::factory()->create();

    // A well-formed uuid that names nothing: this is the ownership check, and it is the
    // case this test always meant to cover. It used to pass 'ghost-family' — which on
    // Postgres never reached the check at all (the uuid column rejected the comparison
    // first), so the test passed on sqlite for the wrong reason. The malformed-input path
    // now has its own pins at the bottom of this file.
    expect(fn () => RefreshToken::issue($user, new IssueContext(familyId: (string) Str::uuid())))
        ->toThrow(InvalidTokenFamilyException::class);
});

it('rejects grafting a token into another user\'s family', function (): void {
    $owner = User::factory()->create();
    $intruder = User::factory()->create();
    $rooted = RefreshToken::issue($owner, new IssueContext);

    expect(fn () => RefreshToken::issue($intruder, new IssueContext(familyId: $rooted->token->family_id)))
        ->toThrow(InvalidTokenFamilyException::class);
});

it('rejects issuing into a reuse-revoked family', function (): void {
    $user = User::factory()->create();
    $a = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));
    RefreshToken::rotate($a->plainText, linkedTo: 'acc-b');

    // Re-presenting the rotated token kills the family via reuse detection.
    RefreshToken::redeem($a->plainText);

    expect(fn () => RefreshToken::issue($user, new IssueContext(familyId: $a->token->family_id)))
        ->toThrow(InvalidTokenFamilyException::class);
});

it('allows inheriting a live family the owner already holds', function (): void {
    $user = User::factory()->create();
    $a = RefreshToken::issue($user, new IssueContext);

    $b = RefreshToken::issue($user, new IssueContext(familyId: $a->token->family_id));

    expect($b->token->family_id)->toBe($a->token->family_id)
        ->and($b->token->revoked_at)->toBeNull();
});

/**
 * The bug this proves (found by the pgsql leg, 2026-07-17): `familyId` is a caller-supplied
 * public API parameter, and `family_id` is a `uuid` column. A malformed value went straight
 * into `->where('family_id', $familyId)`, so on Postgres a host got
 *
 *   SQLSTATE[22P02]: Invalid text representation: invalid input syntax for type uuid
 *
 * — a raw QueryException leaking database internals — instead of the documented
 * InvalidTokenFamilyException. Every engine that actually enforces the uuid type behaved
 * this way; SQLite compares uuid columns as text, so the suite was green for the package's
 * whole life and the very test above ("rejects issuing into a family that does not exist")
 * passed for the wrong reason.
 *
 * Pinned here on EVERY driver, so it cannot regress back into engine-dependence.
 */
it('rejects a malformed family id with the documented exception, on every driver', function (string $familyId): void {
    $user = User::factory()->create();

    expect(fn () => RefreshToken::issue($user, new IssueContext(familyId: $familyId)))
        ->toThrow(InvalidTokenFamilyException::class);
})->with([
    'not a uuid at all' => 'ghost-family',
    'empty' => '',
    'uuid-ish but malformed' => '11111111-2222-3333-4444-55555555555',
    'sql-ish' => "' OR 1=1 --",
]);

/**
 * The counterpart: a well-formed uuid that simply names no family must still be rejected —
 * by the ownership check, not the format guard. Without this, tightening the format could
 * quietly become the ONLY check.
 */
it('rejects a well-formed family id that names no family', function (): void {
    $user = User::factory()->create();

    expect(fn () => RefreshToken::issue($user, new IssueContext(familyId: (string) Str::uuid())))
        ->toThrow(InvalidTokenFamilyException::class);
});
