<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\RefreshTokens\RefreshTokens;

/**
 * @method static \RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken issue(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $owner, \RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext $context)
 * @method static \RoundlyConsulting\RefreshTokens\Support\PendingIssue for(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $owner)
 * @method static \RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult|null redeem(string $plain, ?string $ownerType = null)
 * @method static \RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult|null rotate(string $plain, ?\RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext $context = null)
 * @method static void revoke(\RoundlyConsulting\RefreshTokens\Models\RefreshToken|string $token, ?\RoundlyConsulting\RefreshTokens\Enums\RevocationReason $reason = null)
 * @method static int revokeAllFor(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $owner, \RoundlyConsulting\RefreshTokens\Enums\RevocationReason $reason = \RoundlyConsulting\RefreshTokens\Enums\RevocationReason::LogoutAll)
 * @method static \Illuminate\Support\Collection<int, \RoundlyConsulting\RefreshTokens\Models\RefreshToken> listFor(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $owner)
 * @method static \RoundlyConsulting\RefreshTokens\Models\RefreshToken|null findSession(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $owner, string $familyId)
 * @method static bool revokeSession(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $owner, string $familyId, \RoundlyConsulting\RefreshTokens\Enums\RevocationReason $reason = \RoundlyConsulting\RefreshTokens\Enums\RevocationReason::Logout)
 * @method static int revokeAllExcept(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $owner, ?string $keepFamilyId, \RoundlyConsulting\RefreshTokens\Enums\RevocationReason $reason = \RoundlyConsulting\RefreshTokens\Enums\RevocationReason::LogoutAll)
 * @method static int revokeOthers(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $owner, ?string $currentAccessReference, \RoundlyConsulting\RefreshTokens\Enums\RevocationReason $reason = \RoundlyConsulting\RefreshTokens\Enums\RevocationReason::LogoutAll)
 * @method static int revokeAll(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $owner, \RoundlyConsulting\RefreshTokens\Enums\RevocationReason $reason = \RoundlyConsulting\RefreshTokens\Enums\RevocationReason::LogoutAll)
 * @method static void enrich(\RoundlyConsulting\RefreshTokens\Models\RefreshToken|int|string $session, \RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData $device, ?\RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData $location = null)
 *
 * @see RefreshTokens
 */
final class RefreshToken extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return RefreshTokens::class;
    }
}
