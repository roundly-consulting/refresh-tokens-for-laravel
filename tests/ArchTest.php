<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Actions\RedeemRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeTokenFamilyAction;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;

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
        'Illuminate',
        'Carbon',
        'SensitiveParameter',
        'RuntimeException',
        // native helpers used unqualified
        'app',
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

// Every cryptographic primitive comes from crypto-for-laravel — never a
// third-party library, and never a hand-rolled copy back inside this package. The
// at-rest digest, the HMAC pepper and the CSPRNG must not be re-implemented here.
arch('no crypto primitive is re-implemented locally')
    ->expect('RoundlyConsulting\RefreshTokens')
    ->not->toUse([
        'hash',
        'hash_hmac',
        'hash_equals',
        'random_bytes',
        'random_int',
        'openssl_random_pseudo_bytes',
        'base64_encode',
        'base64_decode',
    ]);

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
            expect($contents)->not->toContain($class, "{$file->getPathname()} imports the internal crypto class {$class}");
        }
    }
});

arch('src never mints or verifies a jwt')
    ->expect('RoundlyConsulting\RefreshTokens')
    ->not->toUse([
        'RoundlyConsulting\Jwt',
    ]);

arch('every source file declares strict types')
    ->expect('RoundlyConsulting\RefreshTokens')
    ->toUseStrictTypes();

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
