<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;
use RoundlyConsulting\PackageToolkit\Exceptions\InvalidConfigurationException;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Support\NullAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Support\RefreshTokenBlueprint;
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

it('mints url-safe plaintexts from the full base64url alphabet', function (): void {
    $hasher = new TokenHasher;

    $tokens = array_map(static fn (): string => $hasher->generate(), range(1, 20));

    foreach ($tokens as $token) {
        expect($token)->toMatch('/^[A-Za-z0-9_-]{64}$/');
    }

    // Distinct every time: the plaintext is CSPRNG-backed, not a counter.
    expect(array_unique($tokens))->toHaveCount(20);
});

it('rejects a token length above the enforced maximum', function (): void {
    config()->set('refresh-tokens.token_length', TokenHasher::MAXIMUM_TOKEN_LENGTH + 1);

    expect(fn (): string => (new TokenHasher)->generate())
        ->toThrow(InvalidTokenConfigurationException::class);
});

it('accepts the maximum token length', function (): void {
    config()->set('refresh-tokens.token_length', TokenHasher::MAXIMUM_TOKEN_LENGTH);

    expect((new TokenHasher)->generate())->toHaveLength(TokenHasher::MAXIMUM_TOKEN_LENGTH);
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

it('resolves the configured key type', function (string $value, KeyType $type): void {
    config()->set('refresh-tokens.key_type', $value);

    expect(TokenModel::keyType())->toBe($type);
})->with([
    // `id` is the value this package shipped before the toolkit's KeyType; the
    // toolkit keeps it as an alias for bigint, so an existing host env keeps working.
    ['id', KeyType::BigInt],
    ['bigint', KeyType::BigInt],
    ['uuid', KeyType::Uuid],
    ['ulid', KeyType::Ulid],
]);

it('falls back to bigint for an unrecognized or non-string key type', function (mixed $value): void {
    // Misconfiguration must never break the schema — it silently degrades to the
    // safe default rather than throwing mid-migration.
    config()->set('refresh-tokens.key_type', $value);

    expect(TokenModel::keyType())->toBe(KeyType::BigInt);
})->with(['guid', '', 123, null]);

it('adds the polymorphic owner columns for every key type', function (KeyType $type): void {
    $table = 'rt_keytype_probe';
    Schema::dropIfExists($table);

    Schema::create($table, function (Blueprint $blueprint) use ($type): void {
        RefreshTokenBlueprint::columns($blueprint, $type);
    });

    expect(Schema::hasColumns($table, ['owner_type', 'owner_id', 'family_started_at', 'absolute_expires_at', 'meta']))->toBeTrue()
        ->and(Schema::hasColumn($table, 'user_id'))->toBeFalse();

    Schema::drop($table);
})->with([KeyType::BigInt, KeyType::Uuid, KeyType::Ulid]);

it('has a no-op default access-token revoker', function (): void {
    $revoker = new NullAccessTokenRevoker;

    $revoker->revoke('anything');

    expect(true)->toBeTrue();
});

it('resolves the configured model class and table', function (): void {
    expect(TokenModel::class())->toBe(RefreshTokenModel::class)
        ->and(TokenModel::make())->toBeInstanceOf(RefreshTokenModel::class)
        ->and(TokenModel::table())->toBe('refresh_tokens');

    config()->set('refresh-tokens.table', '');

    expect(TokenModel::table())->toBe('refresh_tokens');
});

it('throws when the configured model is not a model class', function (): void {
    // The toolkit resolver validates the seam instead of silently swallowing a typo.
    config()->set('refresh-tokens.model', 'not-a-class');

    expect(fn (): string => TokenModel::class())
        ->toThrow(InvalidConfigurationException::class);
});

it('falls back to the packaged model for a real model that is not ours', function (): void {
    // The toolkit resolver only validates "is a Model" — the package must narrow to
    // its own base class, because every call site uses RefreshToken's own API.
    config()->set('refresh-tokens.model', User::class);

    expect(TokenModel::class())->toBe(RefreshTokenModel::class);
});

it('issues via the fluent builder filling ip and user agent from a request', function (): void {
    $user = User::factory()->create();
    $request = Request::create('/refresh', 'POST', server: [
        'REMOTE_ADDR' => '203.0.113.7',
        'HTTP_USER_AGENT' => 'Requester/9',
    ]);

    // A real uuid, not 'fam-9': `family_id` is a uuid column, so a strict engine rejects
    // the comparison outright and the guard in IssueRefreshTokenAction now rejects a
    // malformed id up front on every driver. The old literal only worked because sqlite
    // compares uuid columns as text.
    $familyId = (string) Str::uuid();

    // Seed a live root in the family so inheriting it passes the ownership check.
    RefreshTokenModel::factory()->forOwner($user)->forFamily($familyId)->create();

    $new = RefreshToken::for($user)->fromRequest($request)->inFamily($familyId)->issue();

    expect($new)->toBeInstanceOf(NewRefreshToken::class)
        ->and($new->token->ip_address)->toBe('203.0.113.7')
        ->and($new->token->user_agent)->toBe('Requester/9')
        ->and($new->token->family_id)->toBe($familyId);

    // Also proves IssueContext is what the builder produces.
    expect(new IssueContext(familyId: $familyId))->toBeInstanceOf(IssueContext::class);
});
