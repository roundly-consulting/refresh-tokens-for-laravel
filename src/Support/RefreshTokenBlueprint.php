<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Database\Schema\Blueprint;

/**
 * The canonical column set for the refresh-tokens table. Kept in one place so a
 * host adoption migration (e.g. transforming an existing tokens table) can
 * reproduce the exact shape without duplicating the definition.
 */
final class RefreshTokenBlueprint
{
    public static function columns(Blueprint $table, string $foreignKey = 'user_id'): void
    {
        $table->id();
        $table->unsignedBigInteger($foreignKey)->index();

        // Auth / rotation core.
        $table->string('token_hash', 64)->unique();
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
        $table->timestamp('revoked_at')->nullable();
        $table->timestamps();
        $table->softDeletes();
    }
}
