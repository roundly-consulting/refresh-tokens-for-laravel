<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

beforeEach(function (): void {
    $this->app->instance(AccessTokenRevoker::class, new FakeAccessTokenRevoker);
});

/**
 * Ordering A (family revoked BEFORE the replacement insert commits, so the theft
 * response's snapshot never sees it): the winner's own post-insert dead-family
 * check catches it and self-revokes the replacement, so rotate() returns null and
 * the fresh row is dead.
 */
it('self-revokes a replacement issued into a family reuse killed around the insert', function (): void {
    $user = User::factory()->create();
    $root = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));
    // A sibling we can flip to reuse-detected the instant the replacement inserts.
    $sibling = RefreshToken::issue($user, new IssueContext(
        accessReference: 'acc-sib',
        familyId: $root->token->family_id,
    ));

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $sibling): void {
        if ($raced || ! str_contains($query->sql, 'insert') || ! str_contains($query->sql, 'refresh_tokens')) {
            return;
        }

        $raced = true;

        // A concurrent theft response killed the family; its snapshot ran before this
        // insert committed, so it never revoked the replacement.
        RefreshTokenModel::query()->whereKey($sibling->token->getKey())->update([
            'revoked_at' => now(),
            'revoked_reason' => RevocationReason::ReuseDetected->value,
        ]);
    });

    $rotation = RefreshToken::rotate($root->plainText, new RotationContext(accessReference: 'acc-b'));

    expect($raced)->toBeTrue()
        ->and($rotation)->toBeNull();

    // The replacement exists but is dead — it cannot outlive the family revoke.
    $replacement = RefreshTokenModel::query()
        ->where('family_id', $root->token->family_id)
        ->where('access_reference', 'acc-b')
        ->first();

    expect($replacement)->not->toBeNull()
        ->and($replacement->revoked_at)->not->toBeNull()
        ->and($replacement->revoked_reason)->toBe(RevocationReason::ReuseDetected);
});

/**
 * Ordering B (replacement committed AFTER the theft response's first snapshot): the
 * re-scan loop in RevokeTokenFamilyAction keeps sweeping until a pass revokes zero,
 * so the newly active member is still caught.
 */
it('re-scans and revokes a family member inserted after the first revoke snapshot', function (): void {
    $user = User::factory()->create();
    $root = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));
    $rotation = RefreshToken::rotate($root->plainText, new RotationContext(accessReference: 'acc-b'));
    $replacement = $rotation->newRefreshToken->token;

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $user, $replacement): void {
        // Fire on the family-revoke's membership snapshot only.
        if ($raced || ! str_contains($query->sql, 'select') || ! str_contains($query->sql, 'family_id')) {
            return;
        }

        $raced = true;

        // A late winner commits a fresh active member after the snapshot was taken.
        RefreshTokenModel::factory()
            ->forOwner($user)
            ->forFamily($replacement->family_id)
            ->create(['access_reference' => 'acc-late']);
    });

    // Re-presenting the rotated root triggers reuse detection / the family revoke.
    expect(RefreshToken::redeem($root->plainText))->toBeNull()
        ->and($raced)->toBeTrue();

    $late = RefreshTokenModel::query()->where('access_reference', 'acc-late')->first();

    expect($late->revoked_reason)->toBe(RevocationReason::ReuseDetected)
        ->and($replacement->fresh()->revoked_reason)->toBe(RevocationReason::ReuseDetected);
});

/**
 * Ordering C (reuse lands while the family is MID-rotation — its newest row already
 * claimed by a legitimate refresh, the replacement not yet inserted): the theft
 * response finds no live member to revoke. It must still leave its verdict on the
 * family, or the in-flight replacement is issued into it and the stolen lineage
 * survives the reuse it just exhibited.
 */
it('kills a family whose newest row is mid-rotation when an older token is replayed', function (): void {
    $user = User::factory()->create();
    $a = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));
    $b = RefreshToken::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'))->newRefreshToken;

    // The legitimate holder's refresh has claimed B (the auth path: redeem → mint → issue)…
    $inFlight = RefreshToken::redeem($b->plainText);

    // …when the thief replays the long-rotated A.
    expect(RefreshToken::redeem($a->plainText))->toBeNull();

    // The in-flight replacement must not be born into the killed family.
    expect(fn () => RefreshToken::issue($user, new IssueContext(
        accessReference: 'acc-c',
        familyId: $inFlight->familyId,
    )))->toThrow(InvalidTokenFamilyException::class);

    expect(RefreshTokenModel::query()->forFamily($a->token->family_id)->active()->exists())->toBeFalse();
});

it('kills the family when a strict concurrent redemption of the same token loses', function (): void {
    $user = User::factory()->create();
    $a = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));

    $winner = RefreshToken::redeem($a->plainText);

    // grace = 0: a second presentation of the just-claimed token is reuse, however
    // close in time — the verdict must not depend on whether the winner's replacement
    // happens to be inserted yet.
    expect(RefreshToken::redeem($a->plainText))->toBeNull();

    expect(fn () => RefreshToken::issue($user, new IssueContext(familyId: $winner->familyId)))
        ->toThrow(InvalidTokenFamilyException::class);
});

it('collapses a rotation whose family is killed between its redeem and its issue to null', function (): void {
    $user = User::factory()->create();
    $a = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));
    $b = RefreshToken::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'))->newRefreshToken;

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $a): void {
        // Fire right after rotate()'s own atomic claim of B.
        if ($raced || ! str_starts_with(strtolower($query->sql), 'update') || ! in_array(RevocationReason::Rotated->value, $query->bindings, true)) {
            return;
        }

        $raced = true;

        RefreshToken::redeem($a->plainText); // the thief replays A mid-rotation
    });

    $rotation = RefreshToken::rotate($b->plainText, new RotationContext(accessReference: 'acc-c'));

    expect($raced)->toBeTrue()
        ->and($rotation)->toBeNull()
        ->and(RefreshTokenModel::query()->forFamily($a->token->family_id)->active()->exists())->toBeFalse();
});
