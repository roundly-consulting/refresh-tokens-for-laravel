<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Actions\RedeemRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeTokenFamilyAction;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;

arch('src never references a disallowed runtime vendor')
    ->expect('RoundlyConsulting\RefreshTokens')
    ->not->toUse([
        'Acme',
        'Doctrine',
        'GuzzleHttp',
        'Ramsey',
        'Firebase',
        'Lcobucci',
        'DeviceDetector',
        'WhichBrowser',
        'Jenssegers',
    ]);

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
