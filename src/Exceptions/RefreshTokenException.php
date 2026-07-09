<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Exceptions;

use RuntimeException;

/**
 * Base exception for the refresh-tokens package so hosts can catch every
 * package failure with a single type.
 */
class RefreshTokenException extends RuntimeException {}
