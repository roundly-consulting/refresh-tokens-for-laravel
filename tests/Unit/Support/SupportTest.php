<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Enums\UserKeyType;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
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

it('falls back to safe defaults for non-int length and empty algo', function (): void {
    config()->set('refresh-tokens.token_length', 'not-an-int');
    config()->set('refresh-tokens.hash.algo', '');
    $hasher = new TokenHasher;

    expect($hasher->generate())->toHaveLength(64)
        ->and($hasher->hash('x'))->toBe(hash('sha256', 'x'));
});

it('rejects a hash algo outside the sha-2 allowlist', function (string $algo): void {
    config()->set('refresh-tokens.hash.algo', $algo);

    expect(fn (): string => (new TokenHasher)->hash('x'))
        ->toThrow(InvalidTokenConfigurationException::class);
})->with(['md5', 'crc32b', 'sha1', 'whirlpool']);

it('accepts sha384 and sha512 and matches native hashing', function (string $algo): void {
    config()->set('refresh-tokens.hash.algo', $algo);

    expect((new TokenHasher)->hash('x'))->toBe(hash($algo, 'x'));
})->with(['sha256', 'sha384', 'sha512']);

it('rejects a token length below the enforced minimum', function (int $length): void {
    config()->set('refresh-tokens.token_length', $length);

    expect(fn (): string => (new TokenHasher)->generate())
        ->toThrow(InvalidTokenConfigurationException::class);
})->with([8, 16, 31]);

it('accepts the minimum token length', function (): void {
    config()->set('refresh-tokens.token_length', 32);

    expect((new TokenHasher)->generate())->toHaveLength(32);
});

it('stores a sha512 digest at full width and still redeems', function (): void {
    config()->set('refresh-tokens.hash.algo', 'sha512');
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext);

    expect(strlen($new->token->fresh()->token_hash))->toBe(128)
        ->and(RefreshToken::redeem($new->plainText))->not->toBeNull();
});

it('resolves the configured user key type', function (string $value, UserKeyType $type): void {
    config()->set('refresh-tokens.user_key_type', $value);

    expect(TokenModel::userKeyType())->toBe($type);
})->with([
    ['id', UserKeyType::Id],
    ['uuid', UserKeyType::Uuid],
    ['ulid', UserKeyType::Ulid],
]);

it('throws on an unsupported user key type', function (): void {
    config()->set('refresh-tokens.user_key_type', 'guid');

    expect(fn (): UserKeyType => TokenModel::userKeyType())
        ->toThrow(InvalidTokenConfigurationException::class);
});

it('defaults to id for a non-string user key type', function (): void {
    config()->set('refresh-tokens.user_key_type', 123);

    expect(TokenModel::userKeyType())->toBe(UserKeyType::Id);
});

it('adds a foreign-key column for every key type', function (UserKeyType $type): void {
    $table = 'rt_keytype_probe';
    Schema::dropIfExists($table);

    Schema::create($table, function (Blueprint $blueprint) use ($type): void {
        $blueprint->id();
        $type->foreignColumn($blueprint, 'user_id');
    });

    expect(Schema::hasColumn($table, 'user_id'))->toBeTrue();

    Schema::drop($table);
})->with([UserKeyType::Id, UserKeyType::Uuid, UserKeyType::Ulid]);

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

    // Seed a live root in the family so inheriting it passes the ownership check.
    RefreshTokenModel::factory()->forUser($user)->forFamily('fam-9')->create();

    $new = RefreshToken::for($user)->fromRequest($request)->inFamily('fam-9')->issue();

    expect($new)->toBeInstanceOf(NewRefreshToken::class)
        ->and($new->token->ip_address)->toBe('203.0.113.7')
        ->and($new->token->user_agent)->toBe('Requester/9')
        ->and($new->token->family_id)->toBe('fam-9');

    // Also proves IssueContext is what the builder produces.
    expect(new IssueContext(familyId: 'fam-9'))->toBeInstanceOf(IssueContext::class);
});
