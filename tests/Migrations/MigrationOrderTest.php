<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\PackageToolkit\Support\MigrationPublisher;

/**
 * Migrations are published in directory order, so directory order MUST be
 * dependency order. This package ships exactly one migration today, which makes
 * the ordering trivially correct — and precisely why the pin is written now: the
 * day a second file lands (an ALTER, or a table constrained onto `refresh_tokens`),
 * a sqlite-only suite would happily run a broken order, because SQLite accepts a
 * CREATE TABLE that references a missing parent (messages #27, shops #30, teams #31).
 *
 * The load-bearing assertion is the **structural, engine-independent** one: parse
 * every foreign key out of the sources and assert the parent's CREATE sorts first.
 */

/** @return list<string> */
function orderedSources(): array
{
    $files = glob(__DIR__.'/../../database/migrations/*.php') ?: [];
    sort($files);

    return array_values($files);
}

/**
 * The table each migration CREATEs, keyed by its position in directory order. The
 * package's `Schema::create()` takes a *variable* (the table name is config-driven),
 * so the table is derived from the filename rather than a string literal.
 *
 * @return array<string, int>
 */
function createdTablePositions(): array
{
    $positions = [];

    foreach (orderedSources() as $index => $file) {
        if (preg_match('/^create_(.+)_table$/', MigrationPublisher::nameFor($file), $matches) === 1) {
            $positions[$matches[1]] = $index;
        }
    }

    return $positions;
}

/** Resolve an FK target expression (a literal, or an accessor) to a table name. */
function parentTableFrom(string $expression): ?string
{
    $expression = trim($expression);

    if (preg_match('/^[\'"](.+)[\'"]$/', $expression, $literal) === 1) {
        return $literal[1];
    }

    return match ($expression) {
        'TokenModel::table()' => 'refresh_tokens',
        default => null,
    };
}

it('creates every foreign key target before the table that references it', function (): void {
    $positions = createdTablePositions();
    $altered = 0;

    expect($positions)->toHaveKey('refresh_tokens');

    foreach (orderedSources() as $index => $file) {
        $source = (string) file_get_contents($file);
        $child = MigrationPublisher::nameFor($file);

        // Both of Laravel's FK forms:
        //   ->constrained('parent') / ->constrained(SomeResolver::table())
        //   ->references('id')->on('parent')
        // The argument may itself be a call, so one level of nesting is allowed.
        $argument = '((?:[^()]|\([^()]*\))*)';
        preg_match_all('/->constrained\(\s*'.$argument.'\s*\)/', $source, $constrained);
        preg_match_all('/->on\(\s*'.$argument.'\s*\)/', $source, $referenced);

        foreach ([...$constrained[1], ...$referenced[1]] as $target) {
            $parent = parentTableFrom($target);

            $this->assertNotNull(
                $parent,
                "Could not resolve the FK target `{$target}` in {$child} — teach this pin the new form.",
            );

            $this->assertArrayHasKey(
                $parent,
                $positions,
                "{$child} constrains onto `{$parent}`, which no migration creates.",
            );

            $this->assertLessThan(
                $index,
                $positions[$parent],
                "{$child} (position {$index}) constrains onto `{$parent}`, created at position {$positions[$parent]}.",
            );
        }

        // An ALTER must follow its table's CREATE.
        if (preg_match('/^(?:add|drop|update)_.*_(?:to|from|in|on)_(.+)_table$/', $child, $matches) === 1) {
            $altered++;

            $this->assertArrayHasKey($matches[1], $positions);
            $this->assertLessThan($index, $positions[$matches[1]]);
        }
    }

    // Guard the guard: today the package emits no FK constraint at all (the owner
    // column is a plain indexed key — the host's users table is not ours to
    // constrain) and no ALTER. If either ever changes, the loop above starts biting.
    expect($altered)->toBe(0)
        ->and(str_contains((string) file_get_contents(orderedSources()[0]), '->constrained('))->toBeFalse();
});

it('migrates the published filenames into a fresh empty database', function (): void {
    $directory = sys_get_temp_dir().'/rt_published_'.uniqid();
    File::makeDirectory($directory, recursive: true);

    $timestamp = now();

    foreach (orderedSources() as $offset => $file) {
        File::copy($file, MigrationPublisher::destination(
            MigrationPublisher::nameFor($file),
            $directory,
            $timestamp->copy()->addSeconds($offset),
        ));
    }

    $database = tempnam(sys_get_temp_dir(), 'rtorder').'.sqlite';
    touch($database);

    config()->set('database.connections.order_pin', ['driver' => 'sqlite', 'database' => $database, 'prefix' => '']);
    config()->set('database.default', 'order_pin');
    DB::purge('order_pin');

    expect(Schema::hasTable('refresh_tokens'))->toBeFalse();

    $this->artisan('migrate', ['--path' => $directory, '--realpath' => true])->assertSuccessful();

    expect(Schema::hasTable('refresh_tokens'))->toBeTrue()
        ->and(Schema::hasColumn('refresh_tokens', 'token_hash'))->toBeTrue();

    config()->set('database.default', 'testing');
    DB::purge('order_pin');
    File::deleteDirectory($directory);
});

it('publishes the migrations in directory order', function (): void {
    $timestamp = now();
    $destinations = [];

    foreach (orderedSources() as $offset => $file) {
        $destinations[] = basename(MigrationPublisher::destination(
            MigrationPublisher::nameFor($file),
            '/database/migrations',
            $timestamp->copy()->addSeconds($offset),
        ));
    }

    $sorted = $destinations;
    sort($sorted);

    // The host's migrator runs published files in filename order — which must be the
    // order they were published in.
    expect($destinations)->toBe($sorted)
        ->and($destinations)->toHaveCount(1)
        ->and($destinations[0])->toContain('create_refresh_tokens_table');
});
