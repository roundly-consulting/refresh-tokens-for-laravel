<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
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
