<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * How a redemption attempt failed, as far as a caller may know.
 *
 * `Superseded` is the one benign failure: the token was rotated moments ago (inside
 * `rotation.grace`) and its session lives on — a late duplicate or a lost concurrent
 * refresh. Every other failure — unknown, expired, revoked, reused, another owner type —
 * is `Refused`, indistinguishable from each other.
 */
enum RedemptionFailure: string
{
    use Helpers;

    case None = 'none';             // the redemption succeeded
    case Superseded = 'superseded'; // rotated moments ago; the session lives on
    case Refused = 'refused';       // anything else
}
