<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Database\Factories;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * @extends Factory<RefreshToken>
 */
class RefreshTokenFactory extends Factory
{
    protected $model = RefreshToken::class;

    /**
     * Build the model the host configured in `refresh-tokens.model`, not the packaged one, so a
     * host subclass comes out of the factory with its own events, observers and table.
     *
     * @return class-string<RefreshToken>
     */
    public function modelName(): string
    {
        return TokenModel::class();
    }

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            // A placeholder owner; use forOwner() to attach a real model.
            'owner_type' => 'App\\Models\\User',
            'owner_id' => $this->faker->numberBetween(1, 100000),
            // Never a real plaintext — a random 64-char hex digest stands in for one.
            'token_hash' => hash('sha256', Str::random(64)),
            'family_id' => (string) Str::uuid(),
            'access_reference' => Str::random(32),
            'family_started_at' => CarbonImmutable::now(),
            'expires_at' => CarbonImmutable::now()->addDays(30),
            'revoked_at' => null,
            'revoked_reason' => null,
        ];
    }

    public function expired(): self
    {
        return $this->state(fn (): array => [
            'expires_at' => CarbonImmutable::now()->subDay(),
        ]);
    }

    public function revoked(RevocationReason $reason = RevocationReason::Manual): self
    {
        return $this->state(fn (): array => [
            'revoked_at' => CarbonImmutable::now()->subMinute(),
            'revoked_reason' => $reason,
        ]);
    }

    public function forFamily(string $familyId): self
    {
        return $this->state(fn (): array => [
            'family_id' => $familyId,
        ]);
    }

    public function forOwner(Authenticatable&Model $owner): self
    {
        return $this->state(fn (): array => [
            'owner_type' => $owner->getMorphClass(),
            'owner_id' => $owner->getKey(),
        ]);
    }
}
