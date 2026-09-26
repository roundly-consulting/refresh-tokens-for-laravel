<?php

declare(strict_types=1);

use RoundlyConsulting\PackageToolkit\Enums\DatabaseDriver;
use RoundlyConsulting\RefreshTokens\RefreshTokensServiceProvider;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * This package ships exactly one migration and it declares **no foreign key**: the owner
 * is a polymorphic `owner_type` + `owner_id` pair (any Authenticatable model), and a morph
 * cannot carry a foreign key — nor are the host's owner tables ours to constrain.
 *
 * That shape decides what is worth pinning here, and it is worth being explicit:
 *
 *  - **The R negative control (`toRejectBrokenOrderOnConnection`) is NOT adoptable.** It
 *    asserts the engine *refuses* a reordered set — but reversing a one-file list is the
 *    same list, and with no foreign keys Postgres has nothing to refuse. It would fail
 *    loudly by design ("the engine accepted the broken order"): the assertion working
 *    correctly against a shape it does not fit, not a red to chase.
 *  - **The structural order pin IS kept**, at `foreignKeys: 0`. The row spec did not call
 *    for it (no FK edges, no ALTERs), but this package already carried ~120 lines of
 *    hand-rolled parser doing exactly that job, and deleting it for nothing would lose a
 *    live guard. Pinned at 0, it forces a deliberate update the day an FK arrives rather
 *    than silently starting to matter.
 */
$migrations = __DIR__.'/../../database/migrations';

it('has a runnable migration order', function () use ($migrations): void {
    // `Schema::create(TokenModel::table())` is a config-driven accessor, not a string
    // literal. The resolver never guesses on a non-literal — an unmapped expression FAILS
    // rather than silently dropping the table from the graph, which is what keeps the
    // `foreignKeys: 0` pin honest instead of vacuous.
    expect($migrations)->toHaveRunnableMigrationOrder(
        foreignKeys: 0,
        tableResolvers: ['TokenModel::table()' => 'refresh_tokens'],
    );
});

/**
 * P — the publish-only guards. The fleet publishes migrations timestamped rather than
 * auto-loading them; doing both runs both copies — a duplicate-table failure (bug #5, on
 * three packages). `count: 1` pins the file count so neither check can pass over an empty
 * or relocated directory.
 */
it('never auto-loads its migration — the host publishes it', function (): void {
    expect(RefreshTokensServiceProvider::class)->toNotAutoLoadMigrations();
});

it('publishes its migration timestamp-injected into the host', function (): void {
    expect(RefreshTokensServiceProvider::class)->toPublishMigrationsTimestamped('refresh-tokens-migrations', 1);
});

/**
 * R — the real-engine proof, positive half only (see above for why the negative control
 * does not fit a 0-FK package).
 *
 * This package's DDL had in fact already met Postgres — but only through a bespoke lane
 * that hand-wrote its own raw INSERT and never ran the migration the package ships from a
 * clean database. `migrations: 1` pins the count, and the expectation additionally fails a
 * set that "applies cleanly" while creating no tables — an empty `up()` otherwise passes
 * and proves nothing.
 */
it('applies its migration on postgres', function () use ($migrations): void {
    expect($migrations)->toApplyOnConnection('pgsql', migrations: 1);
})->skip(fn (): bool => ! test()->connectionAvailable('pgsql'), 'no postgres connection available');

/**
 * The driver-truth pin: compares the env-declared driver against what the connection
 * itself answers, so a leg that exports the location vars but not `TESTING_DB_DRIVER`
 * (or a TestCase that decapitates the base case) reds instead of quietly running sqlite
 * and reporting green as a "postgres" job.
 */
it('runs on the driver the leg declared', function (): void {
    expect(DatabaseDriver::current())
        ->toBe(DatabaseDriver::from(DriverMatrix::driver()));
});
