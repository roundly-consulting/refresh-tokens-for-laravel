<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/**
 * Structural race (sqlite, deterministic): revoke the row the instant redeem SELECTs
 * it, so the atomic claim's `WHERE revoked_at IS NULL` update affects zero rows and
 * the losing redemption collapses to null — exercising the race-lost branch without
 * needing real threads.
 */
it('loses the atomic claim when the row is revoked between read and claim', function (): void {
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));

    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$raced, $new): void {
        if ($raced || ! str_contains($query->sql, 'token_hash')) {
            return;
        }

        $raced = true;

        // A concurrent winner claims the row first.
        RefreshTokenModel::query()->whereKey($new->token->getKey())->update([
            'revoked_at' => now(),
            'revoked_reason' => RevocationReason::Rotated->value,
        ]);
    });

    $result = RefreshToken::redeem($new->plainText);

    expect($result)->toBeNull()
        ->and($raced)->toBeTrue()
        // The row was revoked exactly once — no double-spend, reason stays as the winner set it.
        ->and($new->token->fresh()->revoked_reason)->toBe(RevocationReason::Rotated);
});

it('treats a claim lost within the grace window as a benign retry', function (): void {
    config()->set('refresh-tokens.rotation.grace', 60);
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext(accessReference: 'acc-a'));
    $sibling = RefreshToken::issue($user, new IssueContext(
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

    $result = RefreshToken::redeem($new->plainText);

    // Lost the claim but within grace: null, and the family was NOT revoked.
    expect($result)->toBeNull()
        ->and($sibling->token->fresh()->revoked_at)->toBeNull();
});

it('serialises exactly one winner across many redemptions of the same token', function (): void {
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext);

    $results = array_map(fn (): mixed => RefreshToken::redeem($new->plainText), range(1, 5));
    $winners = array_filter($results, fn (mixed $r): bool => $r !== null);

    expect($winners)->toHaveCount(1);
});

/**
 * True concurrency (pgsql CI leg, group `concurrency-pgsql`): two competing conditional
 * claims over two separate connections prove the DB serialises the compare-and-swap —
 * exactly one UPDATE affects a row. Skipped unless a Postgres service is provisioned.
 */
it('lets only one connection win the conditional claim on postgres', function (): void {
    if (getenv('REFRESH_TOKENS_PG') !== '1') {
        $this->markTestSkipped('Postgres double-spend lane runs only when REFRESH_TOKENS_PG=1.');
    }

    config()->set('database.connections.pgsql', [
        'driver' => 'pgsql',
        'host' => getenv('PG_HOST') ?: '127.0.0.1',
        'port' => (int) (getenv('PG_PORT') ?: 5432),
        'database' => getenv('PG_DATABASE') ?: 'testing',
        'username' => getenv('PG_USERNAME') ?: 'postgres',
        'password' => getenv('PG_PASSWORD') ?: 'postgres',
        'prefix' => '',
    ]);
    config()->set('refresh-tokens.table', 'refresh_tokens');

    DB::connection('pgsql')->getSchemaBuilder()->dropAllTables();
    $this->artisan('migrate', ['--database' => 'pgsql', '--path' => 'database/migrations', '--realpath' => true]);

    $key = DB::connection('pgsql')->table('refresh_tokens')->insertGetId([
        'user_id' => 1,
        'token_hash' => hash('sha256', 'pg-race'),
        'family_id' => (string) Str::uuid(),
        'expires_at' => now()->addDay(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $claimOne = DB::connection('pgsql')->table('refresh_tokens')
        ->where('id', $key)->whereNull('revoked_at')->update(['revoked_at' => now()]);

    $claimTwo = DB::connection('pgsql')->table('refresh_tokens')
        ->where('id', $key)->whereNull('revoked_at')->update(['revoked_at' => now()]);

    expect($claimOne)->toBe(1)->and($claimTwo)->toBe(0);
})->group('concurrency-pgsql');
