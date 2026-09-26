<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Database\Schema\Blueprint;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

/**
 * The canonical column set for the refresh-tokens table. Kept in one place so a
 * host adoption migration (e.g. transforming an existing tokens table) can
 * reproduce the exact shape without duplicating the definition.
 *
 * The owner is polymorphic (`owner_type` + `owner_id` + a composite index) and
 * comes from the toolkit's `morphKey()` Blueprint macro, so the key-type mapping
 * (bigint / uuid / ulid) is the fleet's rather than this package's. The macro is
 * registered in the service provider's `register()`, so it exists before the
 * migrator can run.
 */
final class RefreshTokenBlueprint
{
    public static function columns(Blueprint $table, KeyType $keyType = KeyType::BigInt): void
    {
        $table->id();
        $table->morphKey('owner', $keyType, nullable: false);

        // Auth / rotation core. 128 chars fits the widest allowed digest (sha512 hex).
        $table->string('token_hash', 128)->unique();
        $table->uuid('family_id')->index();
        $table->string('access_reference', 64)->nullable()->index();

        // Device metadata (host-supplied via enrich(), carried forward on rotation).
        $table->text('user_agent')->nullable();
        $table->string('browser')->nullable();
        $table->string('browser_version')->nullable();
        $table->string('os')->nullable();
        $table->string('os_version')->nullable();
        $table->string('device_type')->nullable();
        $table->boolean('is_bot')->nullable();

        // Geolocation metadata (host-supplied via enrich(), carried forward on rotation).
        $table->string('country')->nullable();
        $table->string('city')->nullable();
        $table->string('country_code')->nullable();
        $table->string('ip_address', 45)->nullable();

        self::addSessionColumns($table);

        // Lifecycle.
        $table->string('revoked_reason')->nullable();
        $table->timestamp('expires_at')->index();
        $table->timestamp('revoked_at')->nullable()->index();
        $table->timestamps();
        $table->softDeletes();
    }

    /**
     * The session-level columns every row of a family inherits: when the family
     * started, its hard absolute end, and the host's session metadata. Exposed on
     * its own so a host with an existing tokens table can add exactly these in its
     * own migration. All three are nullable, so they can be added to a populated
     * table and backfilled afterwards.
     */
    public static function addSessionColumns(Blueprint $table): void
    {
        $table->timestamp('family_started_at')->nullable();
        $table->timestamp('absolute_expires_at')->nullable();
        $table->jsonb('meta')->nullable();
    }
}
