<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\File;

/**
 * The config contract, pinned in BOTH directions.
 *
 * - Forward: a key the code reads but the package never ships is unreachable — the
 *   host can never set it (shops #30: a whole store-credit feature was dead).
 * - Reverse: a key the package ships but nothing reads is a documented feature that
 *   silently does nothing (alerts #34, media #35).
 *
 * Keys are scraped from real **string tokens**, never the file text — a docblock
 * that merely mentions a key is not a read, and a regex over raw text makes this
 * whole test pass vacuously (media #35 shipped exactly that bug).
 */

/** @return list<string> */
function sourceFiles(bool $withProvider = true): array
{
    $files = [];

    foreach ([__DIR__.'/../../src', __DIR__.'/../../database'] as $directory) {
        foreach (File::allFiles($directory) as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            // The `about` section RENDERS config; rendering a key is not applying it,
            // so the provider must not satisfy the reverse direction on its own
            // (query-builder #42 passed vacuously exactly this way).
            if (! $withProvider && str_ends_with((string) $file->getFilename(), 'ServiceProvider.php')) {
                continue;
            }

            $files[] = (string) $file->getRealPath();
        }
    }

    sort($files);

    return array_values($files);
}

/**
 * Every `refresh-tokens.*` config key the source actually reads, taken from string
 * literals in the token stream.
 *
 * @return list<string>
 */
function configKeysReadBySource(bool $withProvider = true): array
{
    $keys = [];

    foreach (sourceFiles($withProvider) as $file) {
        foreach (token_get_all((string) file_get_contents($file)) as $token) {
            if (! is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }

            $literal = trim($token[1], "'\"");

            if (str_starts_with($literal, 'refresh-tokens.')) {
                $keys[] = $literal;
            }
        }
    }

    return array_values(array_unique($keys));
}

it('reads only keys the shipped config file defines', function (): void {
    /** @var array<string, mixed> $config */
    $config = require __DIR__.'/../../config/refresh-tokens.php';

    $read = configKeysReadBySource();

    // Guard the guard: an empty scrape would make every assertion below vacuous.
    expect($read)->not->toBeEmpty();

    foreach ($read as $key) {
        $this->assertTrue(
            Arr::has($config, substr($key, strlen('refresh-tokens.'))),
            "src/ reads `config('{$key}')`, but config/refresh-tokens.php does not ship it.",
        );
    }
});

it('ships no config key that nothing reads', function (): void {
    /** @var array<string, mixed> $config */
    $config = require __DIR__.'/../../config/refresh-tokens.php';

    // The provider is excluded: an `about` payload that renders a key displays it,
    // it does not apply it. Every shipped key must be read by real behaviour.
    $read = configKeysReadBySource(withProvider: false);

    expect($read)->not->toBeEmpty();

    foreach (array_keys(Arr::dot($config)) as $key) {
        $this->assertContains(
            'refresh-tokens.'.$key,
            $read,
            "config/refresh-tokens.php ships `refresh-tokens.{$key}`, but no line of src/ (outside the provider) ever reads it — a documented feature that does nothing.",
        );
    }
});

it('resolves the storage seam only through Support\\TokenModel', function (): void {
    // The model/table/foreign-key/key-type seam must never be honoured in some call
    // sites and bypassed in others (certificates #26, media #35).
    $seam = ['refresh-tokens.model', 'refresh-tokens.table', 'refresh-tokens.foreign_key', 'refresh-tokens.key_type'];

    foreach (sourceFiles() as $file) {
        if (str_contains($file, '/src/Support/TokenModel.php')) {
            continue;
        }

        foreach (token_get_all((string) file_get_contents($file)) as $token) {
            if (! is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }

            $this->assertNotContains(
                trim($token[1], "'\""),
                $seam,
                basename($file).' reads a storage-seam config key directly — route it through Support\\TokenModel.',
            );
        }
    }
});

it('no longer ships the retired user_key_type key', function (): void {
    /** @var array<string, mixed> $config */
    $config = require __DIR__.'/../../config/refresh-tokens.php';

    // Renamed to `key_type` (env `REFRESH_TOKENS_KEY_TYPE`) on the toolkit's KeyType,
    // which still accepts the old `id` value as an alias for `bigint`.
    expect(Arr::has($config, 'user_key_type'))->toBeFalse()
        ->and(Arr::has($config, 'key_type'))->toBeTrue()
        ->and($config['key_type'])->toBe('bigint');
});
