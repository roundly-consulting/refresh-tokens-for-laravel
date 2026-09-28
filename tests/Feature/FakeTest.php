<?php

declare(strict_types=1);

use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\RefreshTokensManager;
use RoundlyConsulting\RefreshTokens\Testing\RecordedOperation;
use RoundlyConsulting\RefreshTokens\Testing\RefreshTokensFake;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\Client;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

it('installs a manager subtype behind the facade and the container', function (): void {
    $fake = RefreshTokens::fake();

    expect($fake)->toBeInstanceOf(RefreshTokensManager::class)
        ->and(app(RefreshTokensManager::class))->toBe($fake)
        ->and(RefreshTokens::getFacadeRoot())->toBe($fake);
});

it('still performs every call for real', function (): void {
    RefreshTokens::fake();
    $user = User::factory()->create();

    $issued = RefreshTokens::for($user)->issue();

    expect(RefreshTokens::redeem($issued->plainText)?->user->is($user))->toBeTrue()
        ->and(RefreshTokenModel::query()->count())->toBe(1);
});

it('asserts issued tokens, by owner and by context', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();
    $other = User::factory()->create();

    $fake->assertNothingIssued();

    RefreshTokens::for($user)->linkedTo('jti-1')->issue();

    $fake->assertIssued();
    $fake->assertIssued(for: $user);
    $fake->assertIssued($user, fn (IssueContext $context): bool => $context->accessReference === 'jti-1');

    expect(fn () => $fake->assertIssued(for: $other))->toThrow(ExpectationFailedException::class, 'for [')
        ->and(fn () => $fake->assertIssued($user, fn (IssueContext $context): bool => false))->toThrow(ExpectationFailedException::class)
        ->and(fn () => $fake->assertNothingIssued())->toThrow(ExpectationFailedException::class, '1 call(s)');
});

it('asserts an issue made through the injected manager and the trait', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();
    $client = Client::factory()->create();

    app(RefreshTokensManager::class)->issue($client, new IssueContext);
    $user->issueRefreshToken(new IssueContext);

    $fake->assertIssued(for: $client);
    $fake->assertIssued(for: $user);

    expect(array_map(fn (RecordedOperation $op): string => $op->operation, $fake->recorded()))
        ->toBe([RecordedOperation::ISSUE, RecordedOperation::ISSUE]);
});

it('asserts redemptions', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();
    $other = User::factory()->create();
    $issued = RefreshTokens::issue($user, new IssueContext);

    $fake->assertNothingRedeemed();
    expect(fn () => $fake->assertRedeemed())->toThrow(ExpectationFailedException::class);

    RefreshTokens::redeem($issued->plainText);

    $fake->assertRedeemed();
    $fake->assertRedeemed(by: $user);

    expect(fn () => $fake->assertRedeemed(by: $other))->toThrow(ExpectationFailedException::class)
        ->and(fn () => $fake->assertNothingRedeemed())->toThrow(ExpectationFailedException::class);
});

it('records a failed redemption without an owner', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();

    RefreshTokens::redeem('never-issued');

    $fake->assertRedeemed();

    expect(fn () => $fake->assertRedeemed(by: $user))->toThrow(ExpectationFailedException::class)
        ->and($fake->recorded()[0]->count)->toBe(0);
});

it('asserts rotations, recorded as rotations only', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();
    $other = User::factory()->create();
    $issued = RefreshTokens::issue($user, new IssueContext);

    $fake->assertNothingRotated();
    expect(fn () => $fake->assertRotated())->toThrow(ExpectationFailedException::class);

    RefreshTokens::rotate($issued->plainText);

    $fake->assertRotated();
    $fake->assertRotated(for: $user);
    $fake->assertNothingRedeemed();

    expect(fn () => $fake->assertRotated(for: $other))->toThrow(ExpectationFailedException::class)
        ->and(fn () => $fake->assertNothingRotated())->toThrow(ExpectationFailedException::class);
});

it('asserts a revoke by plaintext against the token owner', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();
    $other = User::factory()->create();
    $issued = RefreshTokens::issue($user, new IssueContext);

    $fake->assertNothingRevoked();
    expect(fn () => $fake->assertRevoked())->toThrow(ExpectationFailedException::class);

    RefreshTokens::revoke($issued->plainText);

    $fake->assertRevoked();
    $fake->assertRevoked(for: $user, reason: RevocationReason::Logout);

    expect(fn () => $fake->assertRevoked(for: $other))->toThrow(ExpectationFailedException::class)
        ->and(fn () => $fake->assertRevoked(for: $user, reason: RevocationReason::Security))->toThrow(ExpectationFailedException::class, 'with reason [security]')
        ->and(fn () => $fake->assertNothingRevoked())->toThrow(ExpectationFailedException::class);
});

it('records a revoke of an unknown plaintext without an owner', function (): void {
    $fake = RefreshTokens::fake();

    expect(RefreshTokens::revoke('never-issued'))->toBeFalse();

    $fake->assertRevoked(reason: RevocationReason::Logout);

    expect($fake->recorded()[0]->owner)->toBeNull()
        ->and($fake->recorded()[0]->count)->toBe(0);
});

it('asserts every revoke made through sessions()', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-b'));

    RefreshTokens::sessions($user)->revoke($a->token->family_id, RevocationReason::Security);
    RefreshTokens::sessions($user)->revokeOthers('acc-b', RevocationReason::Manual);
    RefreshTokens::sessions($user)->revokeAllExcept(null, RevocationReason::SessionLimit);
    RefreshTokens::sessions($user)->revokeAll(RevocationReason::CredentialsChanged);

    $fake->assertRevoked(for: $user, reason: RevocationReason::Security);
    $fake->assertRevoked(for: $user, reason: RevocationReason::Manual);
    $fake->assertRevoked(for: $user, reason: RevocationReason::SessionLimit);
    $fake->assertRevoked(for: $user, reason: RevocationReason::CredentialsChanged);

    $revokes = array_values(array_filter($fake->recorded(), fn (RecordedOperation $op): bool => $op->operation === RecordedOperation::REVOKE));

    expect(array_map(fn (RecordedOperation $op): int => $op->count, $revokes))->toBe([1, 0, 1, 0]);
});

it('asserts revokes made through the HasRefreshTokens trait', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();
    $other = User::factory()->create();
    $issued = $user->issueRefreshToken(new IssueContext(accessReference: 'acc-1'));

    expect($user->findSession($issued->token->family_id)?->is($issued->token))->toBeTrue();

    $user->revokeOtherSessions('acc-1');
    $user->revokeSession($issued->token->family_id, RevocationReason::Security);
    $user->revokeAllSessions();

    $fake->assertIssued(for: $user);
    $fake->assertRevoked(for: $user, reason: RevocationReason::Security);
    $fake->assertRevoked(for: $user, reason: RevocationReason::LogoutAll);

    expect(fn () => $fake->assertRevoked(for: $other))->toThrow(ExpectationFailedException::class);
});

it('asserts revokes and enrichment made through session()', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();
    $other = User::factory()->create();
    $issued = RefreshTokens::issue($user, new IssueContext);

    $fake->assertNothingEnriched();
    expect(fn () => $fake->assertEnriched())->toThrow(ExpectationFailedException::class);

    RefreshTokens::session($issued->token->getKey())->enrich(new DeviceData(browser: 'Safari'));
    RefreshTokens::session($issued->token)->revoke(RevocationReason::SessionLimit);

    $fake->assertEnriched();
    $fake->assertEnriched(for: $user);
    $fake->assertRevoked(for: $user, reason: RevocationReason::SessionLimit);

    expect(fn () => $fake->assertEnriched(for: $other))->toThrow(ExpectationFailedException::class)
        ->and(fn () => $fake->assertNothingEnriched())->toThrow(ExpectationFailedException::class);
});

it('asserts prunes', function (): void {
    $fake = RefreshTokens::fake();

    $fake->assertNothingPruned();
    expect(fn () => $fake->assertPruned())->toThrow(ExpectationFailedException::class);

    RefreshTokens::prune(5);

    $fake->assertPruned();

    expect(fn () => $fake->assertNothingPruned())->toThrow(ExpectationFailedException::class);
});

it('records a prune run by the command', function (): void {
    $fake = RefreshTokens::fake();

    $this->artisan('refresh-tokens:prune')->assertSuccessful();

    $fake->assertPruned();
});

it('does not record a call that throws', function (): void {
    $fake = RefreshTokens::fake();
    $user = User::factory()->create();

    expect(fn () => RefreshTokens::issue($user, new IssueContext(ttl: 0)))->toThrow(RuntimeException::class);

    $fake->assertNothingIssued();
    expect($fake)->toBeInstanceOf(RefreshTokensFake::class);
});
