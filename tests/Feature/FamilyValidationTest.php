<?php

declare(strict_types=1);

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

    expect(fn () => RefreshToken::issue($user, new IssueContext(familyId: 'ghost-family')))
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
