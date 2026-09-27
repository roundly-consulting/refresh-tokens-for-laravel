<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\RefreshTokens\Support\RefreshTokenBlueprint;

/**
 * Pins the schema the package emits for **every** `refresh-tokens.key_type` value.
 *
 * The polymorphic owner id column is the one thing this package's schema derives
 * from config, so it is pinned per key type. The `bigint` default is the shipped schema of a
 * security-critical table and must never drift — it is pinned as the exact
 * `CREATE TABLE` string, not a column probe.
 *
 * SQLite renders `uuid` and `ulid` identically (both `varchar`), so this file can
 * only prove they are *strings*. The three types are told apart on a real
 * PostgreSQL server (`bigint` / `uuid` / `character(26)`) — see the row's notes.
 */
function migrateForKeyType(string $keyType): void
{
    $file = tempnam(sys_get_temp_dir(), 'rtschema').'.sqlite';
    touch($file);

    config()->set('database.connections.schema_pin', ['driver' => 'sqlite', 'database' => $file, 'prefix' => '']);
    config()->set('database.default', 'schema_pin');
    config()->set('refresh-tokens.key_type', $keyType);
    DB::purge('schema_pin');

    (require __DIR__.'/../../database/migrations/2026_07_08_000000_create_refresh_tokens_table.php')->up();
}

function createStatement(string $table): string
{
    /** @var object{sql: string}|null $row */
    $row = DB::connection('schema_pin')
        ->selectOne('select sql from sqlite_master where type = ? and name = ?', ['table', $table]);

    return preg_replace('/\s+/', ' ', (string) ($row->sql ?? '')) ?? '';
}

/** @return list<string> */
function indexStatements(string $table): array
{
    /** @var list<object{sql: string}> $rows */
    $rows = DB::connection('schema_pin')->select(
        'select sql from sqlite_master where type = ? and tbl_name = ? and sql is not null order by name',
        ['index', $table],
    );

    return array_values(array_map(
        static fn (object $row): string => (string) preg_replace('/\s+/', ' ', $row->sql),
        $rows,
    ));
}

afterEach(function (): void {
    // Hand the suite's own connection back — Testbench rolls its migrations back
    // against `database.default` when the application is destroyed.
    config()->set('database.default', 'testing');
    DB::purge('schema_pin');
});

it('emits the shipped table byte for byte on the bigint default', function (): void {
    migrateForKeyType('bigint');

    expect(createStatement('refresh_tokens'))->toBe(
        'CREATE TABLE "refresh_tokens" ("id" integer primary key autoincrement not null, '
        .'"owner_type" varchar not null, "owner_id" integer not null, '
        .'"token_hash" varchar not null, "family_id" varchar not null, '
        .'"access_reference" varchar, "user_agent" text, "browser" varchar, "browser_version" varchar, '
        .'"os" varchar, "os_version" varchar, "device_type" varchar, "is_bot" tinyint(1), '
        .'"country" varchar, "city" varchar, "country_code" varchar, "ip_address" varchar, '
        .'"family_started_at" datetime, "absolute_expires_at" datetime, "meta" text, '
        .'"revoked_reason" varchar, "expires_at" datetime not null, "revoked_at" datetime, '
        .'"created_at" datetime, "updated_at" datetime, "deleted_at" datetime)'
    );
});

it('falls back to the bigint table for an unrecognized key type', function (): void {
    migrateForKeyType('id');

    expect(createStatement('refresh_tokens'))->toContain('"owner_id" integer not null');
});

it('emits a string owner key for uuid and ulid owners', function (string $keyType): void {
    migrateForKeyType($keyType);

    expect(createStatement('refresh_tokens'))->toContain('"owner_type" varchar not null, "owner_id" varchar not null');
})->with(['uuid', 'ulid']);

it('falls back to the bigint column for an unrecognized key type', function (): void {
    // KeyType::fromConfig never throws — a typo must not break the schema.
    migrateForKeyType('guid');

    expect(createStatement('refresh_tokens'))->toContain('"owner_id" integer not null');
});

it('indexes exactly the owner morph, auth and lifecycle columns, for every key type', function (string $keyType): void {
    migrateForKeyType($keyType);

    expect(indexStatements('refresh_tokens'))->toBe([
        'CREATE INDEX "refresh_tokens_access_reference_index" on "refresh_tokens" ("access_reference")',
        'CREATE INDEX "refresh_tokens_expires_at_index" on "refresh_tokens" ("expires_at")',
        'CREATE INDEX "refresh_tokens_family_id_index" on "refresh_tokens" ("family_id")',
        'CREATE INDEX "refresh_tokens_owner_type_owner_id_index" on "refresh_tokens" ("owner_type", "owner_id")',
        'CREATE INDEX "refresh_tokens_revoked_at_index" on "refresh_tokens" ("revoked_at")',
        'CREATE UNIQUE INDEX "refresh_tokens_token_hash_unique" on "refresh_tokens" ("token_hash")',
    ]);
})->with(['bigint', 'uuid', 'ulid']);

/**
 * The host-adoption seam: a host with an existing tokens table adds exactly the session
 * columns in its own migration. They must be nullable, or a populated table cannot take
 * them (a NOT NULL column without a default is rejected on a non-empty table).
 */
it('adds the nullable session columns to an existing table', function (): void {
    migrateForKeyType('bigint');

    Schema::connection('schema_pin')->create('legacy_tokens', function (Blueprint $table): void {
        $table->id();
    });
    DB::connection('schema_pin')->table('legacy_tokens')->insert(['id' => 1]);

    Schema::connection('schema_pin')->table('legacy_tokens', function (Blueprint $table): void {
        RefreshTokenBlueprint::addSessionColumns($table);
    });

    expect(createStatement('legacy_tokens'))
        ->toContain('"family_started_at" datetime, "absolute_expires_at" datetime, "meta" text');
});

it('creates the table under the configured name', function (): void {
    config()->set('refresh-tokens.table', 'acme_refresh_tokens');

    migrateForKeyType('bigint');

    expect(createStatement('acme_refresh_tokens'))->toContain('CREATE TABLE "acme_refresh_tokens"');
});
