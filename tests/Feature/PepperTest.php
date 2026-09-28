<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

it('stores an HMAC digest and round-trips issue then redeem under a pepper', function (): void {
    config()->set('refresh-tokens.hash.key', 'pepper-A');
    $user = User::factory()->create();

    $new = RefreshTokens::issue($user, new IssueContext);

    // At rest the digest is the HMAC, not the plain SHA-256 of the same plaintext.
    expect($new->token->token_hash)->toBe(hash_hmac('sha256', $new->plainText, 'pepper-A'))
        ->and($new->token->token_hash)->not->toBe(hash('sha256', $new->plainText));

    $result = RefreshTokens::redeem($new->plainText);

    expect($result)->toBeInstanceOf(RedemptionResult::class)
        ->and($result->user->getAuthIdentifier())->toBe($user->id);
});

it('is byte-identical to plain SHA-256 when no pepper is configured', function (): void {
    config()->set('refresh-tokens.hash.key', null);
    $user = User::factory()->create();

    $new = RefreshTokens::issue($user, new IssueContext);

    expect($new->token->token_hash)->toBe(hash('sha256', $new->plainText));
    expect(RefreshTokens::redeem($new->plainText))->toBeInstanceOf(RedemptionResult::class);
});

it('does not recognise a token minted under a different pepper', function (): void {
    $fake = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $fake);

    config()->set('refresh-tokens.hash.key', 'pepper-A');
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    // Rotate the pepper to a different secret: the old token becomes unknown, not reuse.
    config()->set('refresh-tokens.hash.key', 'pepper-B');

    expect(RefreshTokens::redeem($new->plainText))->toBeNull();

    // Unknown (no matching row) — not a theft signal: nothing is revoked.
    expect($new->token->fresh()->revoked_at)->toBeNull();
    $fake->assertNothingRevoked();
});

it('treats a whitespace-only pepper as no pepper', function (): void {
    config()->set('refresh-tokens.hash.key', '   ');
    $user = User::factory()->create();

    $new = RefreshTokens::issue($user, new IssueContext);

    expect(RefreshTokenModel::query()->whereKey($new->token->getKey())->value('token_hash'))
        ->toBe(hash('sha256', $new->plainText));
    expect(RefreshTokens::redeem($new->plainText))->toBeInstanceOf(RedemptionResult::class);
});
