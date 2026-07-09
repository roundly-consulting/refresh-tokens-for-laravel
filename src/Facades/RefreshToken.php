<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\RefreshTokens\RefreshTokens;

/**
 * @method static \RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken issue(\Illuminate\Contracts\Auth\Authenticatable $user, \RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext $context)
 * @method static \RoundlyConsulting\RefreshTokens\Support\PendingIssue for(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static \RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult|null redeem(string $plain)
 * @method static \RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult|null rotate(string $plain, ?string $linkedTo = null)
 * @method static void revoke(\RoundlyConsulting\RefreshTokens\Models\RefreshToken|string $token)
 * @method static int revokeAllFor(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static \Illuminate\Support\Collection<int, \RoundlyConsulting\RefreshTokens\Models\RefreshToken> listFor(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static int revokeOthers(\Illuminate\Contracts\Auth\Authenticatable $user, ?string $currentAccessReference)
 * @method static int revokeAll(\Illuminate\Contracts\Auth\Authenticatable $user)
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
