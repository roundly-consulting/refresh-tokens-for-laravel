<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\Client;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/**
 * Two isolated account types share the one token table through the polymorphic owner.
 * Their ids collide on purpose (user #1 and client #1): every owner-scoped read and
 * write must key on the morph class AND the id, never the id alone.
 */
beforeEach(function (): void {
    $this->app->instance(AccessTokenRevoker::class, new FakeAccessTokenRevoker);

    $this->user = User::factory()->create();
    $this->client = Client::factory()->create();

    expect($this->user->getKey())->toBe($this->client->getKey());
});

it('stores the owner morph class and id', function (): void {
    $forUser = RefreshToken::issue($this->user, new IssueContext);
    $forClient = RefreshToken::issue($this->client, new IssueContext);

    expect([$forUser->token->owner_type, $forUser->token->owner_id])->toBe([User::class, $this->user->id])
        ->and([$forClient->token->owner_type, $forClient->token->owner_id])->toBe([Client::class, $this->client->id])
        ->and($forUser->token->fresh()->owner)->toBeInstanceOf(User::class)
        ->and($forClient->token->fresh()->owner)->toBeInstanceOf(Client::class);
});

it('lists sessions per owner type without crossing', function (): void {
    RefreshToken::issue($this->user, new IssueContext);
    RefreshToken::issue($this->user, new IssueContext);
    RefreshToken::issue($this->client, new IssueContext);

    expect(RefreshToken::listFor($this->user))->toHaveCount(2)
        ->and(RefreshToken::listFor($this->client))->toHaveCount(1)
        ->and($this->user->refreshTokens()->count())->toBe(2)
        ->and($this->client->sessions()->count())->toBe(1);
});

it('revokes all of one owner without touching the other', function (): void {
    RefreshToken::issue($this->user, new IssueContext);
    $clientSession = RefreshToken::issue($this->client, new IssueContext);

    expect(RefreshToken::revokeAll($this->user))->toBe(1)
        ->and($clientSession->token->fresh()->revoked_at)->toBeNull()
        ->and(RefreshToken::revokeOthers($this->client, null))->toBe(1);
});

it('never finds or revokes another owner type\'s session by family id', function (): void {
    $clientSession = RefreshToken::issue($this->client, new IssueContext);
    $familyId = $clientSession->token->family_id;

    expect(RefreshToken::findSession($this->user, $familyId))->toBeNull()
        ->and(RefreshToken::revokeSession($this->user, $familyId))->toBeFalse()
        ->and(RefreshToken::revokeAllExcept($this->user, null))->toBe(0)
        ->and($clientSession->token->fresh()->revoked_at)->toBeNull()
        ->and(RefreshToken::findSession($this->client, $familyId)?->is($clientSession->token))->toBeTrue();
});

it('rejects inheriting a family that belongs to the same id under another owner type', function (): void {
    $clientSession = RefreshToken::issue($this->client, new IssueContext);

    expect(fn () => RefreshToken::issue($this->user, new IssueContext(familyId: $clientSession->token->family_id)))
        ->toThrow(InvalidTokenFamilyException::class);
});

it('redeems back to the right owner model', function (): void {
    $clientSession = RefreshToken::issue($this->client, new IssueContext);

    $result = RefreshToken::redeem($clientSession->plainText);

    expect($result?->user)->toBeInstanceOf(Client::class)
        ->and($result?->user->is($this->client))->toBeTrue();
});
