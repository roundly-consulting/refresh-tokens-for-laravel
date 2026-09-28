<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Events\SessionRevoked;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenFamilyException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/*
 * A refresh claims the family's newest row BEFORE its replacement exists (the auth path
 * is redeem → mint an access token → issue). For that instant the session has no active
 * row, so a logout that only sweeps active rows finds nothing — and the replacement then
 * lands, carrying the session straight past "log out everywhere" (e.g. the credential-
 * change response to a stolen refresh token that the thief keeps refreshing).
 */

beforeEach(function (): void {
    $this->revoker = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->revoker);
});

function familyIsLive(string $familyId): bool
{
    return RefreshTokenModel::query()->forFamily($familyId)->active()->exists();
}

it('ends a session caught mid-rotation by a global logout', function (): void {
    Event::fake([SessionRevoked::class]);
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    $inFlight = RefreshTokens::redeem($a->plainText);

    expect(RefreshTokens::sessions($user)->revokeAll(RevocationReason::CredentialsChanged))->toBe(1);

    expect(fn () => RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-b', familyId: $inFlight->familyId)))
        ->toThrow(InvalidTokenFamilyException::class);

    expect(familyIsLive($a->token->family_id))->toBeFalse()
        ->and($a->token->fresh()->revoked_reason)->toBe(RevocationReason::CredentialsChanged);

    // The session's last access token is denied, and the end is announced like any revoke.
    $this->revoker->assertRevoked('acc-a');
    Event::assertDispatched(SessionRevoked::class, fn (SessionRevoked $e): bool => $e->familyId === $a->token->family_id
        && $e->reason === RevocationReason::CredentialsChanged
        && $e->accessReference === 'acc-a');
});

it('ends a session caught mid-rotation when that session is revoked by family id', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    $inFlight = RefreshTokens::redeem($a->plainText);

    expect(RefreshTokens::sessions($user)->revoke($inFlight->familyId))->toBeTrue();

    expect(fn () => RefreshTokens::issue($user, new IssueContext(familyId: $inFlight->familyId)))
        ->toThrow(InvalidTokenFamilyException::class);
});

it('seals the other sessions caught mid-rotation but keeps the one asked to be kept', function (): void {
    $user = User::factory()->create();
    $kept = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-kept'));
    $other = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-other'));

    $keptInFlight = RefreshTokens::redeem($kept->plainText);
    $otherInFlight = RefreshTokens::redeem($other->plainText);

    expect(RefreshTokens::sessions($user)->revokeAllExcept($keptInFlight->familyId))->toBe(1);

    expect(fn () => RefreshTokens::issue($user, new IssueContext(familyId: $otherInFlight->familyId)))
        ->toThrow(InvalidTokenFamilyException::class);

    expect(RefreshTokens::issue($user, new IssueContext(familyId: $keptInFlight->familyId))->token->revoked_at)->toBeNull();
});

it('keeps the current session mid-rotation when revoking the others by access reference', function (): void {
    $user = User::factory()->create();
    $current = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-current'));
    $other = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-other'));

    $currentInFlight = RefreshTokens::redeem($current->plainText);
    $otherInFlight = RefreshTokens::redeem($other->plainText);

    expect(RefreshTokens::sessions($user)->revokeOthers('acc-current'))->toBe(1);

    expect(fn () => RefreshTokens::issue($user, new IssueContext(familyId: $otherInFlight->familyId)))
        ->toThrow(InvalidTokenFamilyException::class);

    expect(RefreshTokens::issue($user, new IssueContext(familyId: $currentInFlight->familyId))->token->revoked_at)->toBeNull();
});

it('never touches another owner or a rotation that already completed', function (): void {
    $user = User::factory()->create();
    $bystander = User::factory()->create();

    $done = RefreshTokens::issue($user, new IssueContext);
    $replacement = RefreshTokens::rotate($done->plainText)->newRefreshToken;
    $theirs = RefreshTokens::issue($bystander, new IssueContext);
    $theirsInFlight = RefreshTokens::redeem($theirs->plainText);

    expect(RefreshTokens::sessions($user)->revokeAll())->toBe(1); // the live replacement only

    expect($done->token->fresh()->revoked_reason)->toBe(RevocationReason::Rotated)
        ->and($replacement->token->fresh()->revoked_reason)->toBe(RevocationReason::LogoutAll)
        ->and(RefreshTokens::issue($bystander, new IssueContext(familyId: $theirsInFlight->familyId))->token->revoked_at)->toBeNull();
});

it('self-revokes a replacement whose session was logged out around its insert', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $user): void {
        if ($raced || ! str_starts_with(strtolower($query->sql), 'insert')) {
            return;
        }

        $raced = true;

        // The logout lands the instant the replacement row is written.
        RefreshTokens::sessions($user)->revokeAll(RevocationReason::CredentialsChanged);
    });

    $rotation = RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b'));

    expect($raced)->toBeTrue()
        ->and($rotation)->toBeNull()
        ->and(familyIsLive($a->token->family_id))->toBeFalse();
});

it('collapses a rotation whose session is logged out between its redeem and its issue to null', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $user): void {
        if ($raced || ! str_starts_with(strtolower($query->sql), 'update') || ! in_array(RevocationReason::Rotated->value, $query->bindings, true)) {
            return;
        }

        $raced = true;

        RefreshTokens::sessions($user)->revoke(RefreshTokenModel::query()->sole()->family_id);
    });

    expect(RefreshTokens::rotate($a->plainText, new RotationContext(accessReference: 'acc-b')))->toBeNull()
        ->and($raced)->toBeTrue()
        ->and(familyIsLive($a->token->family_id))->toBeFalse();
});

it('self-revokes a replacement whose family was sealed between its checks and its insert', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $inFlight = RefreshTokens::redeem($a->plainText);

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $user): void {
        // Right after issue()'s pre-insert reuse check has passed.
        if ($raced || ! in_array(RevocationReason::ReuseDetected->value, $query->bindings, true)) {
            return;
        }

        $raced = true;

        RefreshTokens::sessions($user)->revokeAll(RevocationReason::CredentialsChanged);
    });

    $replacement = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-b', familyId: $inFlight->familyId));

    expect($raced)->toBeTrue()
        ->and($replacement->token->revoked_reason)->toBe(RevocationReason::CredentialsChanged)
        ->and($replacement->token->fresh()->revoked_reason)->toBe(RevocationReason::CredentialsChanged)
        ->and(familyIsLive($a->token->family_id))->toBeFalse();
});

it('seals a pending rotation exactly once when two revokes race for it', function (): void {
    Event::fake([SessionRevoked::class]);
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    RefreshTokens::redeem($a->plainText);

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $a): void {
        // After the first revoke has read the pending row, a rival relabels it first.
        if ($raced || ! str_contains($query->sql, 'not exists')) {
            return;
        }

        $raced = true;

        RefreshTokenModel::query()->whereKey($a->token->getKey())->update(['revoked_reason' => RevocationReason::Logout->value]);
    });

    expect(RefreshTokens::sessions($user)->revokeAll())->toBe(0)
        ->and($raced)->toBeTrue()
        ->and($a->token->fresh()->revoked_reason)->toBe(RevocationReason::Logout);

    Event::assertNotDispatched(SessionRevoked::class);
});
