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
use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Support\NullAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Support\PruneWindow;
use RoundlyConsulting\RefreshTokens\Support\RefreshTokenBlueprint;
use RoundlyConsulting\RefreshTokens\Support\RotationGrace;
use RoundlyConsulting\RefreshTokens\Support\Settings;
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

it('throws on a non-int length instead of using 64 (strict config)', function (mixed $length): void {
    config()->set('refresh-tokens.token_length', $length);

    expect(fn (): string => (new TokenHasher)->generate())
        ->toThrow(InvalidTokenConfigurationException::class, 'refresh-tokens.token_length');
})->with(['word' => ['not-an-int'], 'float string' => ['64.5'], 'blank' => [''], 'bool' => [true]]);

it('reads an env-string length and defaults an absent one (strict config)', function (): void {
    config()->set('refresh-tokens.token_length', '48');
    expect((new TokenHasher)->generate())->toHaveLength(48);

    config()->set('refresh-tokens.token_length', null);
    expect((new TokenHasher)->generate())->toHaveLength(64);
});

it('throws on a blank or non-string algo instead of using sha256 (strict config)', function (mixed $algo): void {
    config()->set('refresh-tokens.hash.algo', $algo);

    expect(fn (): string => (new TokenHasher)->hash('x'))->toThrow(InvalidTokenConfigurationException::class);
})->with(['blank' => [''], 'array' => [['sha256']], 'int' => [256]]);

it('hashes with sha256 when the algo is absent (strict config)', function (): void {
    config()->set('refresh-tokens.hash.algo', null);

    expect((new TokenHasher)->hash('x'))->toBe(hash('sha256', 'x'));
});

it('throws on a non-string pepper instead of dropping it (strict config)', function (): void {
    config()->set('refresh-tokens.hash.key', ['pepper']);

    expect(fn (): string => (new TokenHasher)->hash('x'))
        ->toThrow(InvalidTokenConfigurationException::class, 'refresh-tokens.hash.key');
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

    $new = RefreshTokens::issue($user, new IssueContext);

    expect(strlen($new->token->fresh()->token_hash))->toBe(128)
        ->and(RefreshTokens::redeem($new->plainText))->not->toBeNull();
});

it('resolves the configured key type', function (string $value, KeyType $type): void {
    config()->set('refresh-tokens.key_type', $value);

    expect(TokenModel::keyType())->toBe($type);
})->with([
    ['bigint', KeyType::BigInt],
    ['uuid', KeyType::Uuid],
    ['ulid', KeyType::Ulid],
]);

it('reads an absent key type as bigint', function (): void {
    config()->set('refresh-tokens.key_type', null);

    expect(TokenModel::keyType())->toBe(KeyType::BigInt);
});

it('throws on an unrecognized or non-string key type instead of falling back to bigint', function (mixed $value, string $given): void {
    // A typo must stop the app, never silently key a uuid/ulid owner table with bigints.
    // `id` (this package's pre-toolkit spelling) is no longer an alias.
    config()->set('refresh-tokens.key_type', $value);

    expect(fn (): KeyType => TokenModel::keyType())->toThrow(
        InvalidConfigurationException::class,
        "Configuration value [refresh-tokens.key_type] must be one of [bigint, uuid, ulid] (case-insensitive), [{$given}] given.",
    );
})->with([
    'the pre-toolkit id' => ['id', 'id'],
    'a typo' => ['guid', 'guid'],
    'an empty string' => ['', "''"],
    'an integer' => [123, '123'],
]);

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

    config()->set('refresh-tokens.table', null);

    expect(TokenModel::table())->toBe('refresh_tokens');
});

it('throws on a blank or non-string table (strict config)', function (mixed $table): void {
    config()->set('refresh-tokens.table', $table);

    expect(fn (): string => TokenModel::table())
        ->toThrow(InvalidTokenConfigurationException::class, 'refresh-tokens.table');
})->with(['blank' => [''], 'array' => [['tokens']]]);

it('throws on a blank or non-string device type cast (strict config)', function (mixed $cast): void {
    config()->set('refresh-tokens.device_type_cast', $cast);

    expect(fn (): array => (new RefreshTokenModel)->getCasts())
        ->toThrow(InvalidTokenConfigurationException::class, 'refresh-tokens.device_type_cast');
})->with(['blank' => [''], 'int' => [1]]);

it('casts device type with the enum when the cast is absent (strict config)', function (): void {
    config()->set('refresh-tokens.device_type_cast', null);

    expect((new RefreshTokenModel)->getCasts()['device_type'])->toBe(DeviceType::class);
});

it('reads ttls and the grace window strictly (strict config)', function (string $key, mixed $junk): void {
    config()->set($key, $junk);

    expect(fn (): int => match ($key) {
        'refresh-tokens.ttl' => Settings::ttl(),
        'refresh-tokens.absolute_ttl' => Settings::absoluteTtl(),
        'refresh-tokens.rotation.grace' => RotationGrace::seconds(),
    })->toThrow(InvalidTokenConfigurationException::class, $key);
})->with([
    'ttl junk' => ['refresh-tokens.ttl', 'five'],
    'ttl zero' => ['refresh-tokens.ttl', 0],
    'ttl float string' => ['refresh-tokens.ttl', '1.5'],
    'absolute junk' => ['refresh-tokens.absolute_ttl', '90d'],
    'absolute negative' => ['refresh-tokens.absolute_ttl', -1],
    'grace junk' => ['refresh-tokens.rotation.grace', 'soon'],
    'grace negative' => ['refresh-tokens.rotation.grace', '-5'],
]);

it('reads env-string ttls and defaults absent ones (strict config)', function (): void {
    config()->set('refresh-tokens.ttl', '600');
    config()->set('refresh-tokens.absolute_ttl', '0');
    config()->set('refresh-tokens.rotation.grace', ' 30 ');

    expect(Settings::ttl())->toBe(600)
        ->and(Settings::absoluteTtl())->toBe(0)
        ->and(RotationGrace::seconds())->toBe(30);

    config()->set('refresh-tokens.ttl', null);
    config()->set('refresh-tokens.absolute_ttl', null);
    config()->set('refresh-tokens.rotation.grace', null);

    expect(Settings::ttl())->toBe(2_592_000)
        ->and(Settings::absoluteTtl())->toBe(7_776_000)
        ->and(RotationGrace::seconds())->toBe(0);
});

it('hands raw env strings to the strict readers (strict config)', function (): void {
    $_SERVER['REFRESH_TOKENS_TTL'] = 'five';
    $_SERVER['REFRESH_TOKENS_PRUNE_AFTER'] = '7';

    try {
        /** @var array{ttl: mixed, prune: array{after: mixed}} $config */
        $config = require __DIR__.'/../../../config/refresh-tokens.php';
    } finally {
        unset($_SERVER['REFRESH_TOKENS_TTL'], $_SERVER['REFRESH_TOKENS_PRUNE_AFTER']);
    }

    expect($config['ttl'])->toBe('five')
        ->and($config['prune']['after'])->toBe('7');

    config()->set('refresh-tokens.ttl', $config['ttl']);
    config()->set('refresh-tokens.prune.after', $config['prune']['after']);

    expect(fn (): int => Settings::ttl())->toThrow(InvalidTokenConfigurationException::class)
        ->and(PruneWindow::configuredDays())->toBe(7);
});

it('throws when the configured model is not a model class', function (): void {
    // The toolkit resolver validates the seam instead of silently swallowing a typo.
    config()->set('refresh-tokens.model', 'not-a-class');

    expect(fn (): string => TokenModel::class())
        ->toThrow(InvalidConfigurationException::class);
});

it('refuses a foreign model instead of falling back to the packaged one', function (): void {
    // The toolkit refuses any class that is not the packaged model or a subclass of it.
    config()->set('refresh-tokens.model', User::class);

    expect(fn (): string => TokenModel::class())->toThrow(
        InvalidConfigurationException::class,
        'Configuration value [refresh-tokens.model] must be a class-string of ['.RefreshTokenModel::class.'], ['.User::class.'] given.',
    );
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

    $new = RefreshTokens::for($user)->fromRequest($request)->inFamily($familyId)->issue();

    expect($new)->toBeInstanceOf(NewRefreshToken::class)
        ->and($new->token->ip_address)->toBe('203.0.113.7')
        ->and($new->token->user_agent)->toBe('Requester/9')
        ->and($new->token->family_id)->toBe($familyId);

    // Also proves IssueContext is what the builder produces.
    expect(new IssueContext(familyId: $familyId))->toBeInstanceOf(IssueContext::class);
});
