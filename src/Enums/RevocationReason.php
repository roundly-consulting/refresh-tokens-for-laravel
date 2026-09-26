<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Why a refresh token was revoked — written on every revocation so sessions and
 * audit trails can explain how each token died.
 */
enum RevocationReason: string
{
    use Helpers;

    case Rotated = 'rotated';               // superseded by a rotation
    case Logout = 'logout';                 // explicit single-session logout
    case LogoutAll = 'logout_all';          // global logout / revoke-all
    case ReuseDetected = 'reuse_detected';  // family revoke on a theft signal
    case Expired = 'expired';               // swept past expiry
    case Manual = 'manual';                 // admin / host revocation
    case CredentialsChanged = 'credentials_changed'; // password / 2FA / passkey change
    case AccountDisabled = 'account_disabled';       // owner disabled or deleted
    case SessionLimit = 'session_limit';             // evicted by a per-owner session cap
    case Security = 'security';                      // any other security response
}
