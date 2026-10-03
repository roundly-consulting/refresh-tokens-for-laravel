<?php

declare(strict_types=1);

/**
 * The config contract, pinned in BOTH directions.
 *
 *  - Forward — a key the code reads but the package never ships is unreachable: the host
 *    can never set it. That is shops #18, whose whole store-credit feature read
 *    `shops.payments.*` while the file shipped `payment.*`, and 330 tests stayed green
 *    because the suite set the same wrong key.
 *  - Reverse — a key the package ships but nothing reads is a documented feature that
 *    silently does nothing: media #27's `max_file_size` cap that never applied, alerts
 *    #24's thrice-documented `escalation` key, and this package's own dead `load_migrations`.
 *
 * This replaces ~120 lines of hand-rolled tokenizer. The shared assertion is strictly
 * stronger: it also counts reads through an injected config Repository, follows
 * `sectionVariables` offsets to any depth, and FLAGS an interpolated
 * `config("refresh-tokens.{$x}")` rather than silently ignoring it.
 */
it('ships exactly the config keys it reads', function (): void {
    expect(__DIR__.'/../../config/refresh-tokens.php')->toSatisfyConfigContract(
        [__DIR__.'/../../src', __DIR__.'/../../database'],
        [
            // Deliberately NO `excludeFromReverse` for the service provider. The old test
            // here excluded it on the grounds that "rendering a key is not applying it" —
            // the reasoning is sound but the remedy is wrong for this provider shape: the
            // toolkit's PackageServiceProvider both contributesToAbout() (renders) AND
            // bindFromConfig() (real reads) in one file, so excluding it discards the only
            // reader of every bound key and weakens the reverse direction for nothing.
        ],
    );
});
