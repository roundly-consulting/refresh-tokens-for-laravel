<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\RefreshTokens\Support\RefreshTokenBlueprint;

return new class extends Migration
{
    public function up(): void
    {
        $table = config('refresh-tokens.table', 'refresh_tokens');
        $foreignKey = config('refresh-tokens.foreign_key', 'user_id');

        Schema::create(
            is_string($table) ? $table : 'refresh_tokens',
            function (Blueprint $blueprint) use ($foreignKey): void {
                RefreshTokenBlueprint::columns(
                    $blueprint,
                    is_string($foreignKey) && $foreignKey !== '' ? $foreignKey : 'user_id',
                );
            },
        );
    }
};
