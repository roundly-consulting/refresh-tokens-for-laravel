<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Exceptions;

use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;

/**
 * Thrown by {@see FakeAccessTokenRevoker}
 * when one of its assertions fails. It is a package exception (not a PHPUnit
 * assertion) so the fake stays runtime-only and works under any test runner.
 */
final class RevokerAssertionFailedException extends RefreshTokenException {}
