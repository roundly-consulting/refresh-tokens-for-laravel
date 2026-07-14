<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Tests\Fixtures;

use RoundlyConsulting\RefreshTokens\Models\RefreshToken;

/**
 * A host subclass of the packaged model, configured via `refresh-tokens.model`.
 * Every seam the package documents must resolve to THIS class — Eloquent keys
 * model events on the concrete class, so a call site that quietly queries the
 * packaged base instead fires the host's listeners against the wrong model.
 */
final class CustomRefreshToken extends RefreshToken {}
