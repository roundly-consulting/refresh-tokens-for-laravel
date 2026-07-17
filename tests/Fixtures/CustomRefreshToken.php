<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Tests\Fixtures;

use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use RoundlyConsulting\Testing\Fixtures\Concerns\CountsCreations;

/**
 * A host subclass of the packaged model, configured via `refresh-tokens.model`.
 * Every seam the package documents must resolve to THIS class — Eloquent keys
 * model events on the concrete class, so a call site that quietly queries the
 * packaged base instead fires the host's listeners against the wrong model.
 */
final class CustomRefreshToken extends RefreshToken
{
    // Required by `toHonourModelSwap`, not detected. It counts rows created as THIS exact
    // class, which is the only independent proof the swap took effect: `instanceof` is not
    // enough, because a row created as the packaged class never fires the host's model
    // events yet can still satisfy an instanceof check.
    use CountsCreations;
}
