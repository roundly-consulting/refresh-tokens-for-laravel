<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Tests\Fixtures\SwappedTokenTestCase;
use RoundlyConsulting\RefreshTokens\Tests\TestCase;

// Explicit paths, not `->in(__DIR__)`: the ModelSwap directory below needs a different
// base case, and a blanket bind would claim it first. ArchTest.php is listed because
// `swappableModelsAreNotFinal` reads the `refresh-tokens.model` config default and
// `runtimeRequireIsWhitelisted` reads composer.json — both need the app booted, and an
// arch file is not automatically test-cased.
uses(TestCase::class)->in('Unit', 'Feature', 'Concurrency', 'Configured', 'Migrations', 'Provider', 'ArchTest.php');

// The model-swap proofs need `refresh-tokens.model` pointed at the host subclass BEFORE
// the providers boot (and before the migration reads the seam to shape the owner column),
// so they run on their own base case in their own directory — Pest binds a test case per
// directory, not per file.
uses(SwappedTokenTestCase::class)->in('ModelSwap');
