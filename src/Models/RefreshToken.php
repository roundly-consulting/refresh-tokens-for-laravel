<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Models;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\RefreshTokens\Database\Factories\RefreshTokenFactory;
use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * @property int $id
 * @property int|string $user_id
 * @property string $token_hash
 * @property string $family_id
 * @property string|null $access_reference
 * @property string|null $user_agent
 * @property string|null $browser
 * @property string|null $browser_version
 * @property string|null $os
 * @property string|null $os_version
 * @property DeviceType|null $device_type
 * @property bool|null $is_bot
 * @property string|null $country
 * @property string|null $city
 * @property string|null $country_code
 * @property string|null $ip_address
 * @property RevocationReason|null $revoked_reason
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $revoked_at
 * @property CarbonInterface $created_at
 * @property CarbonInterface $updated_at
 * @property CarbonInterface|null $deleted_at
 */
class RefreshToken extends Model
{
    /** @use HasFactory<RefreshTokenFactory> */
    use HasFactory;

    use Prunable;
    use SoftDeletes;

    protected $guarded = [];

    /**
     * Never serialise the at-rest digest or the access-token reference — a "your
     * devices" endpoint that JSON-encodes these models must not leak them. Auth
     * logic reads the raw attributes directly, so hiding them changes nothing there.
     *
     * @var list<string>
     */
    protected $hidden = ['token_hash', 'access_reference'];

    public function getTable(): string
    {
        return TokenModel::table();
    }

    /**
     * Whether the token can still be redeemed: never revoked and not yet expired.
     */
    public function isUsable(): bool
    {
        return $this->revoked_at === null && $this->expires_at->isFuture();
    }

    /**
     * @return BelongsTo<Model, $this>
     */
    public function owner(): BelongsTo
    {
        $userModel = config('refresh-tokens.user_model', 'App\\Models\\User');

        /** @var class-string<Model> $userModel */
        $userModel = is_string($userModel) && $userModel !== '' ? $userModel : 'App\\Models\\User';

        return $this->belongsTo($userModel, TokenModel::foreignKey());
    }

    /**
     * @param  Builder<RefreshToken>  $query
     * @return Builder<RefreshToken>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query
            ->whereNull('revoked_at')
            ->where('expires_at', '>', CarbonImmutable::now());
    }

    /**
     * @param  Builder<RefreshToken>  $query
     * @return Builder<RefreshToken>
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query->where('expires_at', '<=', CarbonImmutable::now());
    }

    /**
     * @param  Builder<RefreshToken>  $query
     * @return Builder<RefreshToken>
     */
    public function scopeForFamily(Builder $query, string $familyId): Builder
    {
        return $query->where('family_id', $familyId);
    }

    /**
     * Rows revoked or expired longer ago than `refresh-tokens.prune.after` days.
     *
     * `self::query()` — deliberately, not `TokenModel::query()`. This is called on
     * whatever model `php artisan model:prune` instantiated, and PHP forwards late
     * static binding through `self::`, so the builder is already the *called* class
     * (a host subclass keeps its own scopes and delete events). Routing it through
     * the config seam would instead prune a host's un-configured subclass as the
     * packaged base class. Pinned in tests/Configured.
     *
     * @return Builder<RefreshToken>
     */
    public function prunable(): Builder
    {
        $after = config('refresh-tokens.prune.after', 30);
        $cutoff = CarbonImmutable::now()->subDays(is_int($after) ? $after : 30);

        return self::query()->where(function (Builder $query) use ($cutoff): void {
            $query
                ->where('revoked_at', '<', $cutoff)
                ->orWhere('expires_at', '<', $cutoff);
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
            'is_bot' => 'boolean',
            'device_type' => DeviceType::class,
            'revoked_reason' => RevocationReason::class,
        ];
    }

    protected static function newFactory(): RefreshTokenFactory
    {
        return RefreshTokenFactory::new();
    }
}
