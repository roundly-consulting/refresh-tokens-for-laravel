<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\RefreshTokens\Support\RefreshTokenBlueprint;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

return new class extends Migration
{
    public function up(): void
    {
        $table = config('refresh-tokens.table', 'refresh_tokens');
        $foreignKey = TokenModel::foreignKey();
        $keyType = TokenModel::userKeyType();

        Schema::create(
            is_string($table) ? $table : 'refresh_tokens',
            function (Blueprint $blueprint) use ($foreignKey, $keyType): void {
                RefreshTokenBlueprint::columns($blueprint, $foreignKey, $keyType);
            },
        );
    }
};
