<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Enums;

use RoundlyConsulting\Enums\Helpers;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;

/**
 * The class of device a session was created from. The host supplies this as
 * already-parsed input via {@see DeviceData};
 * this package never parses a user agent itself.
 */
enum DeviceType: string
{
    use Helpers;

    case Desktop = 'desktop';
    case Mobile = 'mobile';
    case Tablet = 'tablet';
    case Bot = 'bot';
    case Unknown = 'unknown';
}
