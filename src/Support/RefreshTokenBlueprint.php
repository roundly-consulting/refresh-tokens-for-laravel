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
 * The owner column comes from the toolkit's `ownerKey()` Blueprint macro, so the
 * key-type mapping (bigint / uuid / ulid) is the fleet's rather than this
 * package's. The macro is registered in the service provider's `register()`, so
 * it exists before the migrator can run.
 */
final class RefreshTokenBlueprint
{
    public static function columns(
        Blueprint $table,
        string $foreignKey = 'user_id',
        KeyType $keyType = KeyType::BigInt,
    ): void {
        $table->id();
        $table->ownerKey($foreignKey, $keyType);

        // Auth / rotation core. 128 chars fits the widest allowed digest (sha512 hex).
        $table->string('token_hash', 128)->unique();
        $table->uuid('family_id')->index();
        $table->string('access_reference', 64)->nullable()->index();

        // Device metadata (host-supplied via enrich()).
        $table->text('user_agent')->nullable();
        $table->string('browser')->nullable();
        $table->string('browser_version')->nullable();
        $table->string('os')->nullable();
        $table->string('os_version')->nullable();
        $table->string('device_type')->nullable();
        $table->boolean('is_bot')->nullable();

        // Geolocation metadata (host-supplied via enrich()).
        $table->string('country')->nullable();
        $table->string('city')->nullable();
        $table->string('country_code')->nullable();
        $table->string('ip_address', 45)->nullable();

        // Lifecycle.
        $table->string('revoked_reason')->nullable();
        $table->timestamp('expires_at')->index();
        $table->timestamp('revoked_at')->nullable()->index();
        $table->timestamps();
        $table->softDeletes();
    }
}
