<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * Structural race (sqlite, deterministic): revoke the row the instant redeem SELECTs
 * it, so the atomic claim's `WHERE revoked_at IS NULL` update affects zero rows and
 * the losing redemption collapses to null — exercising the race-lost branch without
 * needing real threads.
 */
it('loses the atomic claim when the row is revoked between read and claim', function (): void {
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $claimedAt = now()->subSecond()->startOfSecond();

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $new, $claimedAt): void {
        if ($raced || ! str_contains($query->sql, 'token_hash')) {
            return;
        }

        $raced = true;

        // A concurrent winner claims the row first.
        RefreshTokenModel::query()->whereKey($new->token->getKey())->update([
            'revoked_at' => $claimedAt,
            'revoked_reason' => RevocationReason::Rotated->value,
        ]);
    });

    $result = RefreshTokens::redeem($new->plainText);
    $row = $new->token->fresh();

    expect($result)->toBeNull()
        ->and($raced)->toBeTrue()
        // The row was claimed exactly once — no double-spend: the winner's claim stands…
        ->and($row->revoked_at->equalTo($claimedAt))->toBeTrue()
        // …and, rotation being strict (grace 0), the loser's presentation is reuse: its
        // verdict marks the family so the winner's replacement cannot extend it.
        ->and($row->revoked_reason)->toBe(RevocationReason::ReuseDetected);
});

it('treats a claim lost within the grace window as a benign retry', function (): void {
    config()->set('refresh-tokens.rotation.grace', 60);
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $sibling = RefreshTokens::issue($user, new IssueContext(
        accessReference: 'acc-b',
        familyId: $new->token->family_id,
    ));

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $new): void {
        if ($raced || ! str_contains($query->sql, 'token_hash')) {
            return;
        }

        $raced = true;

        RefreshTokenModel::query()->whereKey($new->token->getKey())->update([
            'revoked_at' => now(),
            'revoked_reason' => RevocationReason::Rotated->value,
        ]);
    });

    $result = RefreshTokens::redeem($new->plainText);

    // Lost the claim but within grace: null, and the family was NOT revoked.
    expect($result)->toBeNull()
        ->and($sibling->token->fresh()->revoked_at)->toBeNull();
});

it('keeps the one-winner guarantee under owner-type scoping', function (): void {
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext);

    $results = array_map(fn (): mixed => RefreshTokens::redeem($new->plainText, User::class), range(1, 5));

    expect(array_filter($results, fn (mixed $r): bool => $r !== null))->toHaveCount(1);
});

it('serialises exactly one winner across many redemptions of the same token', function (): void {
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext);

    $results = array_map(fn (): mixed => RefreshTokens::redeem($new->plainText), range(1, 5));
    $winners = array_filter($results, fn (mixed $r): bool => $r !== null);

    expect($winners)->toHaveCount(1);
});

/**
 * True concurrency on a real engine: two competing redemptions of the same token over two
 * separate connections prove the database serialises the compare-and-swap — exactly one
 * wins.
 *
 * ## What replaced the bespoke `--group=concurrency-pgsql` lane, and why it is stronger
 *
 * This package used to run its own Postgres job (`PG_USERNAME`/`PG_PASSWORD`, a targeted
 * `pest --group=concurrency-pgsql` lane). That convention is deleted in favour of the
 * fleet's whole-suite `TESTING_DB_*` leg. The old lane had three holes this closes:
 *
 *  1. **It gated on `getenv('REFRESH_TOKENS_PG') !== '1'`** — it asked whether an env var
 *     was *set*, never whether an engine was *reachable*. A leg that lost its service
 *     still reported green. The gate is now `DriverMatrix::driver()`, i.e. the connection
 *     the suite is actually on.
 *  2. **It never ran the package's code.** It hand-wrote a raw INSERT and two raw
 *     `->update()` calls, so it proved that *Postgres* honours `WHERE revoked_at IS NULL`
 *     — a fact about Postgres, not about refresh-tokens. `RefreshTokens::redeem()` was
 *     never on the pgsql path. This drives the real facade flow, so the claim under test
 *     is the one the package ships.
 *  3. **It was a lane, so only tagged tests met the engine.** Divergence is not
 *     predictable in advance: the shops pilot's real find surfaced in an ordinary domain
 *     test nobody would have tagged. Now the whole suite runs on Postgres and this case is
 *     simply one of them.
 *
 * The one thing the lane did that a single-connection suite cannot: drive **two real
 * sessions**. That is preserved here, and is why this case still exists at all.
 */
it('lets only one connection win the conditional claim on postgres', function (): void {
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $claimedAt = now()->subSecond()->startOfSecond();

    // A second, independent session against the same database — a real concurrent
    // connection, not another handle on the transaction under test.
    config()->set('database.connections.rival', DriverMatrix::connectionConfig('pgsql'));
    DB::purge('rival');

    // The rival claims the row first, through the same conditional-claim SQL the package's
    // redeem() issues.
    $claimed = DB::connection('rival')->table('refresh_tokens')
        ->where('id', $new->token->getKey())
        ->whereNull('revoked_at')
        ->update(['revoked_at' => $claimedAt, 'revoked_reason' => RevocationReason::Rotated->value]);

    expect($claimed)->toBe(1);

    // Now the package's real redemption races in behind it and must LOSE — the atomic
    // claim affects zero rows, so the redemption collapses to null rather than minting a
    // second live token from a token already spent. A double-spend here is two valid
    // sessions from one refresh token.
    expect(RefreshTokens::redeem($new->plainText))->toBeNull();

    // Claimed exactly once, by the winner (its timestamp stands); the strict loser's
    // presentation is reuse, so the row now carries the family's reuse verdict.
    $row = $new->token->fresh();

    expect(RefreshTokenModel::query()->whereKey($new->token->getKey())->count())->toBe(1)
        ->and($row->revoked_at->equalTo($claimedAt))->toBeTrue()
        ->and($row->revoked_reason)->toBe(RevocationReason::ReuseDetected);
})->skip(fn (): bool => DriverMatrix::driver() !== 'pgsql', 'true concurrency is only observable on a real engine');
