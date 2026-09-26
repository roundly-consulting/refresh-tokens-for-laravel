<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\SessionRevoked;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

beforeEach(function (): void {
    $this->spy = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->spy);
});

it('lists only active sessions, newest first', function (): void {
    $user = User::factory()->create();

    RefreshTokenModel::factory()->forOwner($user)->create();
    RefreshTokenModel::factory()->forOwner($user)->expired()->create();
    RefreshTokenModel::factory()->forOwner($user)->revoked()->create();
    $newest = RefreshTokenModel::factory()->forOwner($user)->create();

    $sessions = RefreshToken::listFor($user);

    expect($sessions)->toHaveCount(2)
        ->and($sessions->first()->is($newest))->toBeTrue();
});

it('revokes a single session, denies its access reference, and is idempotent', function (): void {
    Event::fake([SessionRevoked::class]);
    $user = User::factory()->create();
    $session = RefreshTokenModel::factory()->forOwner($user)->create(['access_reference' => 'acc-x']);

    RefreshToken::revoke($session);
    RefreshToken::revoke($session); // second call must be a no-op

    expect($session->fresh()->revoked_at)->not->toBeNull()
        ->and($session->fresh()->revoked_reason)->toBe(RevocationReason::Manual)
        ->and($this->spy->revoked)->toBe(['acc-x']);

    Event::assertDispatchedTimes(SessionRevoked::class, 1);
});

it('revokeOthers keeps the current session and revokes the rest', function (): void {
    $user = User::factory()->create();
    $current = RefreshTokenModel::factory()->forOwner($user)->create(['access_reference' => 'current']);
    RefreshTokenModel::factory()->forOwner($user)->create(['access_reference' => 'other-1']);
    RefreshTokenModel::factory()->forOwner($user)->create(['access_reference' => 'other-2']);

    $count = RefreshToken::revokeOthers($user, 'current');

    $denied = $this->spy->revoked;
    sort($denied);

    expect($count)->toBe(2)
        ->and($current->fresh()->revoked_at)->toBeNull()
        ->and(RefreshToken::listFor($user))->toHaveCount(1)
        ->and($denied)->toBe(['other-1', 'other-2']);
});

it('revokeAll and revokeAllFor revoke every active session', function (): void {
    $user = User::factory()->create();
    RefreshTokenModel::factory()->count(3)->forOwner($user)->create();

    expect(RefreshToken::revokeAll($user))->toBe(3)
        ->and(RefreshToken::listFor($user))->toHaveCount(0);

    RefreshTokenModel::factory()->count(2)->forOwner($user)->create();
    expect(RefreshToken::revokeAllFor($user))->toBe(2);
});

it('logs out by plaintext, revoking exactly the matching row', function (): void {
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-logout'));
    RefreshToken::issue($user, new IssueContext); // an unrelated session

    RefreshToken::revoke($new->plainText);

    expect($new->token->fresh()->revoked_at)->not->toBeNull()
        ->and($new->token->fresh()->revoked_reason)->toBe(RevocationReason::Logout)
        ->and($this->spy->revoked)->toBe(['acc-logout'])
        ->and(RefreshToken::listFor($user))->toHaveCount(1);
});

it('ignores logout for an unknown plaintext', function (): void {
    RefreshToken::revoke('never-issued');

    expect($this->spy->revoked)->toBe([]);
});

it('finds the active row of a family, owner-scoped', function (): void {
    $user = User::factory()->create();
    $other = User::factory()->create();
    $root = RefreshToken::issue($user, new IssueContext);
    $rotation = RefreshToken::rotate($root->plainText);
    $familyId = $root->token->family_id;

    expect(RefreshToken::findSession($user, $familyId)?->is($rotation?->newRefreshToken->token))->toBeTrue()
        ->and(RefreshToken::findSession($other, $familyId))->toBeNull()
        ->and(RefreshToken::findSession($user, (string) Str::uuid()))->toBeNull()
        ->and($user->findSession($familyId)?->is($rotation?->newRefreshToken->token))->toBeTrue();

    RefreshToken::revokeSession($user, $familyId);

    expect(RefreshToken::findSession($user, $familyId))->toBeNull();
});

it('answers a malformed family id with null or false, before any query', function (string $familyId): void {
    $user = User::factory()->create();
    $queries = 0;
    DB::listen(function (QueryExecuted $query) use (&$queries): void {
        $queries++;
    });

    expect(RefreshToken::findSession($user, $familyId))->toBeNull()
        ->and(RefreshToken::revokeSession($user, $familyId))->toBeFalse()
        ->and($queries)->toBe(0);
})->with(['not-a-uuid', '', "' OR 1=1 --"]);

it('revokes every active row of a family, denying each access reference once', function (): void {
    Event::fake([SessionRevoked::class]);
    $user = User::factory()->create();
    $familyId = (string) Str::uuid();

    // A grace-window rotation can leave two active rows in one family.
    $a = RefreshTokenModel::factory()->forOwner($user)->forFamily($familyId)->create(['access_reference' => 'acc-1']);
    $b = RefreshTokenModel::factory()->forOwner($user)->forFamily($familyId)->create(['access_reference' => 'acc-2']);
    $untouched = RefreshTokenModel::factory()->forOwner($user)->create(['access_reference' => 'acc-3']);

    expect(RefreshToken::revokeSession($user, $familyId, RevocationReason::Security))->toBeTrue()
        ->and($a->fresh()->revoked_reason)->toBe(RevocationReason::Security)
        ->and($b->fresh()->revoked_reason)->toBe(RevocationReason::Security)
        ->and($untouched->fresh()->revoked_at)->toBeNull()
        ->and($this->spy->revoked)->toBe(['acc-1', 'acc-2'])
        // Nothing left to revoke: false, and no second denial.
        ->and(RefreshToken::revokeSession($user, $familyId))->toBeFalse()
        ->and($this->spy->revoked)->toHaveCount(2);

    Event::assertDispatchedTimes(SessionRevoked::class, 2);
    Event::assertDispatched(
        SessionRevoked::class,
        fn (SessionRevoked $e): bool => $e->tokenId === $a->getKey()
            && $e->familyId === $familyId
            && $e->ownerType === User::class
            && $e->ownerId === $user->id
            && $e->reason === RevocationReason::Security
            && $e->accessReference === 'acc-1',
    );
});

it('defaults revokeSession to the logout reason and exposes it on the owner', function (): void {
    $user = User::factory()->create();
    $session = RefreshToken::issue($user, new IssueContext);

    expect($user->revokeSession($session->token->family_id))->toBeTrue()
        ->and($session->token->fresh()->revoked_reason)->toBe(RevocationReason::Logout);
});

it('revokes all but the kept family', function (): void {
    $user = User::factory()->create();
    $current = RefreshToken::issue($user, new IssueContext(accessReference: 'current'));
    RefreshToken::issue($user, new IssueContext(accessReference: 'other-1'));
    RefreshToken::issue($user, new IssueContext(accessReference: 'other-2'));

    expect(RefreshToken::revokeAllExcept($user, $current->token->family_id, RevocationReason::CredentialsChanged))->toBe(2)
        ->and($current->token->fresh()->revoked_at)->toBeNull()
        ->and(RefreshToken::listFor($user))->toHaveCount(1)
        ->and(RefreshTokenModel::query()->where('revoked_reason', RevocationReason::CredentialsChanged->value)->count())->toBe(2);
});

it('matches the kept family case-insensitively', function (): void {
    $user = User::factory()->create();
    $current = RefreshToken::issue($user, new IssueContext);
    RefreshToken::issue($user, new IssueContext);

    expect(RefreshToken::revokeAllExcept($user, strtoupper($current->token->family_id)))->toBe(1)
        ->and($current->token->fresh()->revoked_at)->toBeNull();
});

it('revokes everything when the kept family is null or unrecognisable', function (?string $keep): void {
    $user = User::factory()->create();
    RefreshToken::issue($user, new IssueContext);
    RefreshToken::issue($user, new IssueContext);

    expect(RefreshToken::revokeAllExcept($user, $keep))->toBe(2)
        ->and(RefreshToken::listFor($user))->toHaveCount(0);
})->with(['null' => null, 'malformed' => 'not-a-uuid']);

it('persists the reason given to every revoke verb', function (): void {
    $user = User::factory()->create();

    $plain = RefreshToken::issue($user, new IssueContext);
    RefreshToken::revoke($plain->plainText, RevocationReason::AccountDisabled);

    $row = RefreshToken::issue($user, new IssueContext);
    RefreshToken::revoke($row->token, RevocationReason::SessionLimit);

    $others = RefreshToken::issue($user, new IssueContext(accessReference: 'keep'));
    RefreshToken::issue($user, new IssueContext);
    RefreshToken::revokeOthers($user, 'keep', RevocationReason::CredentialsChanged);

    expect($plain->token->fresh()->revoked_reason)->toBe(RevocationReason::AccountDisabled)
        ->and($row->token->fresh()->revoked_reason)->toBe(RevocationReason::SessionLimit)
        ->and(RefreshTokenModel::query()->where('revoked_reason', RevocationReason::CredentialsChanged->value)->count())->toBe(1)
        ->and(RefreshToken::revokeAllFor($user, RevocationReason::AccountDisabled))->toBe(1)
        ->and($others->token->fresh()->revoked_reason)->toBe(RevocationReason::AccountDisabled)
        ->and($user->revokeAllSessions(RevocationReason::Security))->toBe(0);
});
