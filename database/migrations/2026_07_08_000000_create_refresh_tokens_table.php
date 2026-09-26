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
        $keyType = TokenModel::keyType();

        Schema::create(
            TokenModel::table(),
            function (Blueprint $blueprint) use ($keyType): void {
                RefreshTokenBlueprint::columns($blueprint, $keyType);
            },
        );
    }
};
