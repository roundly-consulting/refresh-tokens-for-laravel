<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Tests\Fixtures;

use RoundlyConsulting\RefreshTokens\Tests\TestCase;
use RoundlyConsulting\Testing\Concerns\SwapsConfiguredModels;

/**
 * The base case for the model-swap proofs: `refresh-tokens.model` points at the host
 * subclass BEFORE the providers boot.
 *
 * Boot order is the whole point, and it is load-bearing twice over in this package:
 *
 *  1. a provider hangs observers and listeners on whatever class `refresh-tokens.model`
 *     names at boot, so a swap applied afterwards leaves them on the packaged class and
 *     the host's model events silently never fire; and
 *  2. **the migration itself reads the seam** — `TokenModel::table()` and
 *     `::keyType()` shape the table and its owner column — so a swap set in a test body is read only
 *     after the table already exists. A swap test written that way is structurally
 *     incapable of catching a migration-time bug, which is exactly how `reviews` shipped
 *     a passing swap test for the bug it was named for.
 *
 * This lives in its own directory because Pest binds a test case per DIRECTORY, not per
 * file.
 */
abstract class SwappedTokenTestCase extends TestCase
{
    use SwapsConfiguredModels;

    protected function defineEnvironment($app): void
    {
        // MUST call parent: PackageTestCase does its whole job in defineEnvironment()
        // (DriverMatrix::configure + configBeforeBoot + the swaps). Overriding without
        // parent:: silently decapitates the base case — no error, no red, DriverMatrix
        // simply never configured, and the pgsql leg quietly runs sqlite.
        $this->swapModel('refresh-tokens.model', CustomRefreshToken::class);

        parent::defineEnvironment($app);
    }
}
