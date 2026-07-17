<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Actions\RedeemRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeTokenFamilyAction;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\Exceptions\RefreshTokenException;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\Testing\Arch\ArchPresets;

// Our own crypto-for-laravel is allowed — it owns the digest and CSPRNG
// primitives — but any accidental `use` of a third-party crypto/token library
// fails the suite.
arch('src only uses allowed vendor roots')
    ->expect('RoundlyConsulting\RefreshTokens')
    ->toOnlyUse([
        'RoundlyConsulting\RefreshTokens',
        'RoundlyConsulting\RefreshTokens\Database\Factories',
        'RoundlyConsulting\Crypto',
        'RoundlyConsulting\Enums',
        'RoundlyConsulting\PackageToolkit',
        'Illuminate',
        'Carbon',
        'SensitiveParameter',
        'RuntimeException',
        // native helpers used unqualified
        'app',
        'class_basename',
        'config',
        'config_path',
        'database_path',
        'now',
        '__',
    ]);

arch('no forbidden runtime vendors are imported')
    ->expect([
        'Doctrine',
        'GuzzleHttp',
        'Ramsey',
        'Firebase',
        'Lcobucci',
        'DeviceDetector',
        'WhichBrowser',
        'Jenssegers',
    ])
    ->not->toBeUsed();

/**
 * Every cryptographic primitive comes from crypto-for-laravel — never a third-party
 * library, and never a hand-rolled copy back inside this package. The at-rest digest, the
 * HMAC pepper and the CSPRNG must not be re-implemented here.
 *
 * This replaces the bespoke ban list that stood here. The preset is a superset of it in
 * every direction that matters (it also bans the openssl and sodium families, and
 * hash_pbkdf2), with one deliberate subtraction: `hash_equals` is NOT banned. It IS PHP's
 * constant-time compare rather than a re-implementation of one, it has no algorithm or key
 * to centralise, and banning it pushes callers toward `$a === $b` — a timing leak in
 * exactly the code that compares a token digest. The fleet removed it from the shared
 * preset on 2026-07-17; this package was one of six still banning it in a local list that
 * never read the shared one.
 */
ArchPresets::noLocalCryptoPrimitives('RoundlyConsulting\RefreshTokens');

// Str::random is a general-purpose helper, not a token mint: plaintext secrets
// come from Crypto\Random\Token so the entropy floor lives in one audited place.
arch('src never mints a token with Str::random')
    ->expect('RoundlyConsulting\RefreshTokens')
    ->not->toUse('Illuminate\Support\Str::random');

// Only crypto's PUBLIC surface is ours to use: whatever crypto tags `@internal`
// today or tomorrow, this package must not import it, so an internal refactor of
// crypto can never break refresh-tokens.
it('imports no crypto class tagged @internal', function (): void {
    $cryptoSrc = realpath(__DIR__.'/../vendor/roundly-consulting/crypto-for-laravel/src');

    expect($cryptoSrc)->toBeString();

    /** @var list<string> $internal */
    $internal = [];

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator((string) $cryptoSrc, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());

        if (! str_contains($contents, '@internal')) {
            continue;
        }

        if (preg_match('/^namespace\s+([^;]+);/m', $contents, $namespace) === 1) {
            $internal[] = trim($namespace[1]).'\\'.$file->getBasename('.php');
        }
    }

    // Sanity: crypto really does tag something internal (guards a silent no-op).
    expect($internal)->not->toBeEmpty();

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator((string) realpath(__DIR__.'/../src'), FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());

        foreach ($internal as $class) {
            // This read `expect($contents)->not->toContain($class, "…message…")`, and that
            // call is **vacuous**: Pest's `toContain` is variadic, so the message was taken
            // as a SECOND NEEDLE, and `not->toContain(a, b)` passes whenever a and b are
            // not both present — which, for a message that never appears in source, is
            // always. The ban could not fail. Asserted through `str_contains` so the
            // message stays a message.
            expect(str_contains($contents, $class))->toBeFalse(
                "{$file->getPathname()} imports the internal crypto class {$class}",
            );
        }
    }
});

arch('src never mints or verifies a jwt')
    ->expect('RoundlyConsulting\RefreshTokens')
    ->not->toUse([
        'RoundlyConsulting\Jwt',
    ]);

ArchPresets::strictTypes('RoundlyConsulting\RefreshTokens');

/**
 * The deliberate tension, run as a pair. `finalByDefault` wants every class closed;
 * `swappableModelsAreNotFinal` forbids `final` on a config-swappable model — a PHP fatal
 * the moment a host uses the seam the config documents, shipped 7x across the fleet.
 *
 * Exempt here: RefreshToken, which `refresh-tokens.model` invites a host to subclass
 * (pinned by the preset below instead), and RefreshTokenException, the base every
 * refresh-tokens error extends so a host can catch them uniformly.
 */
// The exemptions go through the preset's `$ignoring` PARAMETER, not Pest's `->ignoring()`.
// Only the parameter is checked for staleness: `::class` on a non-existent class is not a
// PHP error (it resolves to a string at compile time), so an exemption that has outlived
// the code it excused silences nothing and says nothing — leaving the ban applying where
// you believe it does not. The README's own example uses the unchecked form for this
// preset; the parameter is strictly better and costs nothing.
ArchPresets::finalByDefault('RoundlyConsulting\RefreshTokens', [
    RefreshTokenModel::class,
    RefreshTokenException::class,
]);

/**
 * `refresh-tokens.user_model` is deliberately NOT listed. It is not a swappable *package*
 * model: it names the HOST's own user class, which this package never ships, never
 * subclasses and cannot pin a default for (the default is the literal string
 * 'App\Models\User', a class that does not exist here). `toHonourModelSwap` and this
 * preset both assert against a packaged model and its shipped default, so neither has
 * anything to say about it. The one real seam is `refresh-tokens.model`.
 */
ArchPresets::swappableModelsAreNotFinal([
    RefreshTokenModel::class => 'refresh-tokens.model',
]);

/**
 * `modelsResolveThroughSeam` is **REJECTED for this package, with cause** — and the cause
 * is a false positive, so it is reported rather than worked around.
 *
 * The preset reds on `Models/RefreshToken.php`, for `self::query()` in `prunable()`. That
 * call is **correct, deliberate, and documented at the call site**, and routing it through
 * the seam as the preset demands would introduce the very bug the preset exists to
 * prevent:
 *
 *   `prunable()` is an instance method that `php artisan model:prune` calls on the model
 *   the HOST configured. `self::` is a PHP **forwarding call**, so it preserves late static
 *   binding — verified, not assumed: for `class Sub extends Base`, `(new Sub)->viaSelf()`
 *   where `viaSelf()` does `self::who()` returns `Sub`, not `Base`. The builder is
 *   therefore already the *called* (host) class, keeping its scopes and delete events.
 *   Replacing it with `TokenModel::query()` would prune a host's un-configured subclass AS
 *   the packaged base class.
 *
 * This is jwt's rejection reason recurring on a *model* (jwt's was a non-model, which the
 * preset has since been narrowed to allow). By the plan's own rule — "if a second package
 * hits this, it is a package defect, not a row problem" — this is now a testing-package
 * defect: the preset is an unconditional token ban registered as an `it()` case, so it has
 * no `->ignoring()` escape and no way to say "this LSB is the correct one". Reported for a
 * fix there rather than patched here.
 *
 * **No coverage is lost by the rejection.** The behaviour the preset would have guarded is
 * already pinned *behaviourally* — which is strictly stronger than a token scan — by
 * `tests/Configured/ConfiguredModelTest.php`: "prunes through the configured model, not the
 * packaged base class" drives a real `model:prune` against a host subclass and asserts the
 * concrete class of every pruned row. The stray-literal half is likewise covered: every
 * `refresh-tokens.model` read already goes through the TokenModel seam, pinned by the same
 * file's swap tests.
 */

/**
 * The morph-key seam, guarded. Refresh-tokens has NO polymorphic column — the one
 * `create_refresh_tokens_table` migration keys sessions off a plain user id, not a morph.
 * The pin still adopts, and it is NOT vacuous: it scans the real migration file (which
 * exists and is non-empty) and correctly finds no raw morph, so it passes on evidence
 * rather than on an empty parse. If a future migration ever adds a `$table->morphs()` here
 * instead of routing through `morphKey(..., KeyType::fromConfig(...))`, this reds — the same
 * stop the morph packages get, installed before column 1 rather than after.
 */
ArchPresets::morphColumnsUseTheSeam(__DIR__.'/../database/migrations');

/**
 * The Dependency Policy as a test. No `alsoAllow`: this package's `require` ships only
 * php/illuminate/roundly, and the workflow installs test tooling with `--dev`. If this
 * goes red the shipped graph is wrong — never widen the allow-list to quiet it.
 */
ArchPresets::runtimeRequireIsWhitelisted(__DIR__.'/../composer.json');

ArchPresets::noDebuggingLeftovers();

arch('exceptions extend the base runtime exception')
    ->expect('RoundlyConsulting\RefreshTokens\Exceptions')
    ->toExtend('RuntimeException');

arch('src never touches the DB facade — Eloquent only')
    ->expect('RoundlyConsulting\RefreshTokens')
    ->not->toUse('Illuminate\Support\Facades\DB');

arch('DTOs are final and readonly')
    ->expect('RoundlyConsulting\RefreshTokens\DataTransferObjects')
    ->toBeFinal()
    ->toBeReadonly();

it('never calls save() or forceFill() in the redeem/claim path', function (string $class): void {
    $source = file_get_contents((string) (new ReflectionClass($class))->getFileName());

    expect($source)
        ->not->toContain('->save(')
        ->not->toContain('->forceFill(');
})->with([
    RedeemRefreshTokenAction::class,
    RevokeTokenFamilyAction::class,
    RevokeSessionAction::class,
]);

it('marks every plaintext parameter as sensitive', function (array $target): void {
    [$class, $method] = $target;

    $parameters = (new ReflectionMethod($class, $method))->getParameters();
    $plain = array_values(array_filter(
        $parameters,
        fn (ReflectionParameter $p): bool => in_array($p->getName(), ['plain', 'accessReference'], true),
    ));

    expect($plain)->not->toBeEmpty();

    foreach ($plain as $parameter) {
        expect($parameter->getAttributes(SensitiveParameter::class))->not->toBeEmpty();
    }
})->with([
    [[RefreshTokenManager::class, 'redeem']],
    [[RefreshTokenManager::class, 'revoke']],
    [[RefreshTokens::class, 'redeem']],
    [[TokenHasher::class, 'hash']],
    [[AccessTokenRevoker::class, 'revoke']],
]);
