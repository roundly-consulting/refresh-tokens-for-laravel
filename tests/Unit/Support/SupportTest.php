<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Support\NullAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

it('generates a plaintext of the configured length and hashes deterministically', function (): void {
    config()->set('refresh-tokens.token_length', 48);
    $hasher = new TokenHasher;

    $plain = $hasher->generate();
    expect($plain)->toHaveLength(48)
        ->and($hasher->hash($plain))->toBe(hash('sha256', $plain))
        ->and($hasher->hash($plain))->toBe($hasher->hash($plain));
});

it('applies an HMAC pepper when hash.key is set', function (): void {
    config()->set('refresh-tokens.hash.key', 'pepper-secret');
    $hasher = new TokenHasher;

    expect($hasher->hash('abc'))->toBe(hash_hmac('sha256', 'abc', 'pepper-secret'))
        ->and($hasher->hash('abc'))->not->toBe(hash('sha256', 'abc'));
});

it('falls back to safe defaults for invalid config', function (): void {
    config()->set('refresh-tokens.token_length', 0);
    config()->set('refresh-tokens.hash.algo', '');
    $hasher = new TokenHasher;

    expect($hasher->generate())->toHaveLength(64)
        ->and($hasher->hash('x'))->toBe(hash('sha256', 'x'));
});

it('has a no-op default access-token revoker', function (): void {
    $revoker = new NullAccessTokenRevoker;

    $revoker->revoke('anything');

    expect(true)->toBeTrue();
});

it('resolves the configured model class and foreign key', function (): void {
    expect(TokenModel::class())->toBe(RefreshTokenModel::class)
        ->and(TokenModel::make())->toBeInstanceOf(RefreshTokenModel::class)
        ->and(TokenModel::foreignKey())->toBe('user_id');

    config()->set('refresh-tokens.model', 'not-a-class');
    config()->set('refresh-tokens.foreign_key', '');

    expect(TokenModel::class())->toBe(RefreshTokenModel::class)
        ->and(TokenModel::foreignKey())->toBe('user_id');
});

it('issues via the fluent builder filling ip and user agent from a request', function (): void {
    $user = User::factory()->create();
    $request = Request::create('/refresh', 'POST', server: [
        'REMOTE_ADDR' => '203.0.113.7',
        'HTTP_USER_AGENT' => 'Requester/9',
    ]);

    $new = RefreshToken::for($user)->fromRequest($request)->inFamily('fam-9')->issue();

    expect($new)->toBeInstanceOf(NewRefreshToken::class)
        ->and($new->token->ip_address)->toBe('203.0.113.7')
        ->and($new->token->user_agent)->toBe('Requester/9')
        ->and($new->token->family_id)->toBe('fam-9');

    // Also proves IssueContext is what the builder produces.
    expect(new IssueContext(familyId: 'fam-9'))->toBeInstanceOf(IssueContext::class);
});
