<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
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

    $rotation = RefreshToken::rotate($new->plainText, linkedTo: 'acc-new');

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
            && $e->userId === $user->id,
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

    RefreshToken::rotate($new->plainText, linkedTo: 'acc-new');

    // The redeem of the old token, plus the issue of the replacement.
    Event::assertDispatchedTimes(RefreshTokenRedeemed::class, 1);
    Event::assertDispatchedTimes(RefreshTokenIssued::class, 2);
});
