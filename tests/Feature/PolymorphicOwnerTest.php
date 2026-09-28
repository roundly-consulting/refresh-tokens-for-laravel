<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\Client;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\PublicIdUser;
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
    $forUser = RefreshTokens::issue($this->user, new IssueContext);
    $forClient = RefreshTokens::issue($this->client, new IssueContext);

    expect([$forUser->token->owner_type, $forUser->token->owner_id])->toBe([User::class, $this->user->id])
        ->and([$forClient->token->owner_type, $forClient->token->owner_id])->toBe([Client::class, $this->client->id])
        ->and($forUser->token->fresh()->owner)->toBeInstanceOf(User::class)
        ->and($forClient->token->fresh()->owner)->toBeInstanceOf(Client::class);
});

it('lists sessions per owner type without crossing', function (): void {
    RefreshTokens::issue($this->user, new IssueContext);
    RefreshTokens::issue($this->user, new IssueContext);
    RefreshTokens::issue($this->client, new IssueContext);

    expect(RefreshTokens::sessions($this->user)->all())->toHaveCount(2)
        ->and(RefreshTokens::sessions($this->client)->all())->toHaveCount(1)
        ->and($this->user->refreshTokens()->count())->toBe(2)
        ->and($this->client->sessions()->count())->toBe(1);
});

it('revokes all of one owner without touching the other', function (): void {
    RefreshTokens::issue($this->user, new IssueContext);
    $clientSession = RefreshTokens::issue($this->client, new IssueContext);

    expect(RefreshTokens::sessions($this->user)->revokeAll())->toBe(1)
        ->and($clientSession->token->fresh()->revoked_at)->toBeNull()
        ->and(RefreshTokens::sessions($this->client)->revokeOthers(null))->toBe(1);
});

it('never finds or revokes another owner type\'s session by family id', function (): void {
    $clientSession = RefreshTokens::issue($this->client, new IssueContext);
    $familyId = $clientSession->token->family_id;

    expect(RefreshTokens::sessions($this->user)->find($familyId))->toBeNull()
        ->and(RefreshTokens::sessions($this->user)->revoke($familyId))->toBeFalse()
        ->and(RefreshTokens::sessions($this->user)->revokeAllExcept(null))->toBe(0)
        ->and($clientSession->token->fresh()->revoked_at)->toBeNull()
        ->and(RefreshTokens::sessions($this->client)->find($familyId)?->is($clientSession->token))->toBeTrue();
});

it('rejects inheriting a family that belongs to the same id under another owner type', function (): void {
    $clientSession = RefreshTokens::issue($this->client, new IssueContext);

    expect(fn () => RefreshTokens::issue($this->user, new IssueContext(familyId: $clientSession->token->family_id)))
        ->toThrow(InvalidTokenFamilyException::class);
});

it('redeems back to the right owner model', function (): void {
    $clientSession = RefreshTokens::issue($this->client, new IssueContext);

    $result = RefreshTokens::redeem($clientSession->plainText);

    expect($result?->user)->toBeInstanceOf(Client::class)
        ->and($result?->user->is($this->client))->toBeTrue();
});

/*
 * `owner_id` is a morph key: `owner()` (MorphTo) and `refreshTokens()` (MorphMany)
 * resolve it through the model's KEY. Storing the auth identifier instead breaks the
 * round trip for a model whose identifier is another column — here user #1's public id
 * is "2", so its token came back owned by user #2.
 */
it('keys the owner by the model key even when the auth identifier is another column', function (): void {
    $first = PublicIdUser::query()->create(['name' => '2']);
    $second = PublicIdUser::query()->create(['name' => '1']);

    $issued = RefreshTokens::issue($first, new IssueContext);

    expect($issued->token->owner_id)->toBe($first->getKey())
        ->and($first->refreshTokens()->count())->toBe(1)
        ->and($second->refreshTokens()->count())->toBe(0)
        ->and(RefreshTokens::sessions($first)->all())->toHaveCount(1)
        ->and(RefreshTokens::sessions($second)->all())->toHaveCount(0);

    $redeemed = RefreshTokens::redeem($issued->plainText);

    expect($redeemed?->user->is($first))->toBeTrue();
});
