<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/*
 * The lifecycle running on crypto-for-laravel's Digest + Token: issue → redeem →
 * rotate → reuse-detect, under every supported algorithm, peppered and not. This
 * is the thin end-to-end proof that swapping the primitives changed nothing that
 * a host can observe.
 */

beforeEach(function (): void {
    $this->revoker = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->revoker);
});

it('issues, redeems, rotates and reuse-detects on every algorithm and pepper', function (string $algo, ?string $pepper): void {
    config()->set('refresh-tokens.hash.algo', $algo);
    config()->set('refresh-tokens.hash.key', $pepper);

    $user = User::factory()->create();

    // Issue: only the digest is stored, and it is the crypto digest of the plaintext.
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    expect($a->plainText)->toMatch('/^[A-Za-z0-9_-]{64}$/')
        ->and($a->token->token_hash)->toBe((new TokenHasher)->hash($a->plainText))
        ->and($a->token->token_hash)->not->toContain($a->plainText);

    // Rotate: the replacement is live, the presented token is dead.
    $b = RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    expect($b)->not->toBeNull()
        ->and($b->newRefreshToken->plainText)->not->toBe($a->plainText)
        ->and($a->token->fresh()->revoked_reason)->toBe(RevocationReason::Rotated)
        ->and($b->newRefreshToken->token->fresh()->revoked_at)->toBeNull();

    // The replacement itself rotates — the digest lookup still finds its row.
    $c = RefreshTokens::rotate($b->newRefreshToken->plainText, new RotationContext(accessReference: 'acc-c'));

    expect($c)->not->toBeNull()
        ->and($c->redeemedFamilyId)->toBe($a->token->family_id);

    // Reuse of the long-dead token A kills the family and denies the live reference.
    expect(RefreshTokens::redeem($a->plainText))->toBeNull();

    $this->revoker->assertRevoked('acc-c');
    expect($c->newRefreshToken->token->fresh()->revoked_reason)->toBe(RevocationReason::ReuseDetected);
})->with([
    ['sha256', null],
    ['sha384', null],
    ['sha512', null],
    ['sha256', 'pepper-integration'],
    ['sha384', 'pepper-integration'],
    ['sha512', 'pepper-integration'],
]);

it('cannot redeem a token minted under a different pepper', function (): void {
    config()->set('refresh-tokens.hash.key', 'pepper-A');
    $user = User::factory()->create();

    $new = RefreshTokens::issue($user, new IssueContext);

    // Rotating the pepper invalidates the at-rest digest — by design.
    config()->set('refresh-tokens.hash.key', 'pepper-B');

    expect(RefreshTokens::redeem($new->plainText))->toBeNull();
});

it('never lets a weak configuration mint a token', function (): void {
    config()->set('refresh-tokens.token_length', 16);
    $user = User::factory()->create();

    expect(fn () => RefreshTokens::issue($user, new IssueContext))
        ->toThrow(InvalidTokenConfigurationException::class);
});
