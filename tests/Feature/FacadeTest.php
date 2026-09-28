<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use RoundlyConsulting\RefreshTokens\Actions\ListSessionsAction;
use RoundlyConsulting\RefreshTokens\Contracts\AccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\DeviceData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\LocationData;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RedemptionResult;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationResult;
use RoundlyConsulting\RefreshTokens\Enums\DeviceType;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Exceptions\SessionNotFoundException;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\RefreshTokensManager;
use RoundlyConsulting\RefreshTokens\Support\OwnerSessions;
use RoundlyConsulting\RefreshTokens\Support\PendingIssue;
use RoundlyConsulting\RefreshTokens\Support\SessionHandle;
use RoundlyConsulting\RefreshTokens\Testing\FakeAccessTokenRevoker;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\Client;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

beforeEach(function (): void {
    $this->spy = new FakeAccessTokenRevoker;
    $this->app->instance(AccessTokenRevoker::class, $this->spy);
});

it('pins the facade contract', function (): void {
    expect(RefreshTokens::class)
        ->toDocumentItsRoot()
        ->toBeFakeable()
        ->toReachEveryAction(__DIR__.'/../../src/Actions');
});

it('is registered under the RefreshTokens alias and never clashes with the model', function (): void {
    $composer = json_decode((string) file_get_contents(__DIR__.'/../../composer.json'), true);

    expect($composer['extra']['laravel']['aliases'])->toBe(['RefreshTokens' => RefreshTokens::class])
        ->and(class_basename(RefreshTokens::class))->not->toBe(class_basename(RefreshTokenModel::class))
        ->and(class_basename(RefreshTokensManager::class))->not->toBe(class_basename(RefreshTokens::class));
});

it('issues through the fluent builder', function (): void {
    $user = User::factory()->create();
    $request = Request::create('/refresh', 'POST', server: ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'PestBrowser/1.0']);

    $pending = RefreshTokens::for($user);
    $new = $pending->fromRequest($request)->linkedTo('jti-1')->ttl(3600)->meta(['guard' => 'users'])->issue();

    expect($pending)->toBeInstanceOf(PendingIssue::class)
        ->and($new)->toBeInstanceOf(NewRefreshToken::class)
        ->and($new->token->ip_address)->toBe('203.0.113.9')
        ->and($new->token->access_reference)->toBe('jti-1')
        ->and($new->token->meta)->toBe(['guard' => 'users'])
        ->and($new->token->owner()->is($user))->toBeTrue();
});

it('issues, redeems, rotates and revokes by plaintext', function (): void {
    $user = User::factory()->create();

    $issued = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-1'));
    $redeemed = RefreshTokens::redeem($issued->plainText);

    expect($redeemed)->toBeInstanceOf(RedemptionResult::class)
        ->and($redeemed?->user->is($user))->toBeTrue();

    $second = RefreshTokens::issue($user, new IssueContext);
    $rotated = RefreshTokens::rotate($second->plainText, new RotationContext(accessReference: 'acc-2'));

    expect($rotated)->toBeInstanceOf(RotationResult::class)
        ->and($rotated?->redeemedFamilyId)->toBe($second->token->family_id)
        ->and($rotated?->newRefreshToken->token->access_reference)->toBe('acc-2');

    $plain = (string) $rotated?->newRefreshToken->plainText;

    expect(RefreshTokens::revoke($plain))->toBeTrue()
        ->and(RefreshTokens::revoke($plain))->toBeFalse()
        ->and(RefreshTokens::revoke('never-issued'))->toBeFalse()
        ->and($rotated?->newRefreshToken->token->fresh()?->revoked_reason)->toBe(RevocationReason::Logout)
        ->and($this->spy->revoked)->toBe(['acc-2']);
});

it('revokes by plaintext with an explicit reason', function (): void {
    $user = User::factory()->create();
    $issued = RefreshTokens::issue($user, new IssueContext);

    RefreshTokens::revoke($issued->plainText, RevocationReason::AccountDisabled);

    expect($issued->token->fresh()?->revoked_reason)->toBe(RevocationReason::AccountDisabled);
});

it('manages one owner\'s sessions through sessions()', function (): void {
    $user = User::factory()->create();
    $a = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));
    $b = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-b'));
    $c = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-c'));

    $sessions = RefreshTokens::sessions($user);

    expect($sessions)->toBeInstanceOf(OwnerSessions::class)
        ->and($sessions->owner->is($user))->toBeTrue()
        ->and($sessions->all())->toHaveCount(3)
        ->and($sessions->find($a->token->family_id)?->is($a->token))->toBeTrue()
        ->and($sessions->revoke($a->token->family_id, RevocationReason::Security))->toBeTrue()
        ->and($a->token->fresh()?->revoked_reason)->toBe(RevocationReason::Security)
        ->and($sessions->revokeOthers('acc-b'))->toBe(1)
        ->and($c->token->fresh()?->revoked_at)->not->toBeNull()
        ->and($sessions->all()->pluck('id')->all())->toBe([$b->token->id]);
});

it('revokes all sessions except a kept family, and all of them', function (): void {
    $user = User::factory()->create();
    $keep = RefreshTokens::issue($user, new IssueContext);
    RefreshTokens::issue($user, new IssueContext);
    RefreshTokens::issue($user, new IssueContext);

    expect(RefreshTokens::sessions($user)->revokeAllExcept($keep->token->family_id))->toBe(2)
        ->and(RefreshTokens::sessions($user)->all()->pluck('id')->all())->toBe([$keep->token->id])
        ->and(RefreshTokens::sessions($user)->revokeAll(RevocationReason::CredentialsChanged))->toBe(1)
        ->and($keep->token->fresh()?->revoked_reason)->toBe(RevocationReason::CredentialsChanged)
        ->and(RefreshTokens::sessions($user)->all())->toBeEmpty();
});

it('refuses another owner\'s session through sessions()', function (): void {
    $alice = User::factory()->create();
    $bob = User::factory()->create();
    $bobs = RefreshTokens::issue($bob, new IssueContext(accessReference: 'acc-bob'));
    $family = $bobs->token->family_id;

    expect(RefreshTokens::sessions($alice)->find($family))->toBeNull()
        ->and(RefreshTokens::sessions($alice)->revoke($family))->toBeFalse()
        ->and(RefreshTokens::sessions($alice)->revokeAll())->toBe(0)
        ->and(RefreshTokens::sessions($alice)->revokeOthers(null))->toBe(0)
        ->and(RefreshTokens::sessions($alice)->revokeAllExcept(null))->toBe(0)
        ->and($bobs->token->fresh()?->revoked_at)->toBeNull()
        ->and($this->spy->revoked)->toBe([]);
});

it('refuses a same-id owner of another type through sessions()', function (): void {
    $user = User::factory()->create();
    $client = Client::factory()->create();

    expect($client->getKey())->toBe($user->getKey());

    $users = RefreshTokens::issue($user, new IssueContext);

    expect(RefreshTokens::sessions($client)->find($users->token->family_id))->toBeNull()
        ->and(RefreshTokens::sessions($client)->revoke($users->token->family_id))->toBeFalse()
        ->and(RefreshTokens::sessions($client)->revokeAll())->toBe(0)
        ->and($users->token->fresh()?->revoked_at)->toBeNull();
});

it('enriches and revokes one row through session()', function (): void {
    $user = User::factory()->create();
    $issued = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-row'));

    $handle = RefreshTokens::session($issued->token);
    $handle->enrich(new DeviceData(browser: 'Firefox', deviceType: DeviceType::Desktop), new LocationData(country: 'Slovakia', countryCode: 'SK'));

    $row = $issued->token->fresh();

    expect($handle)->toBeInstanceOf(SessionHandle::class)
        ->and($row?->browser)->toBe('Firefox')
        ->and($row?->country_code)->toBe('SK')
        ->and($handle->revoke())->toBeTrue()
        ->and($handle->revoke())->toBeFalse()
        ->and($issued->token->fresh()?->revoked_reason)->toBe(RevocationReason::Manual)
        ->and($this->spy->revoked)->toBe(['acc-row']);
});

it('addresses a session row by key', function (): void {
    $user = User::factory()->create();
    $issued = RefreshTokens::issue($user, new IssueContext);

    RefreshTokens::session($issued->token->getKey())->enrich(new DeviceData(os: 'Linux'));

    expect(RefreshTokens::session((string) $issued->token->getKey())->revoke(RevocationReason::SessionLimit))->toBeTrue()
        ->and($issued->token->fresh()?->os)->toBe('Linux')
        ->and($issued->token->fresh()?->revoked_reason)->toBe(RevocationReason::SessionLimit)
        ->and(fn () => RefreshTokens::session(999_999)->revoke())->toThrow(SessionNotFoundException::class);
});

it('prunes through the facade', function (): void {
    $user = User::factory()->create();
    $old = RefreshTokenModel::factory()->forOwner($user)->create(['revoked_at' => now()->subDays(40), 'revoked_reason' => RevocationReason::Logout]);
    $live = RefreshTokenModel::factory()->forOwner($user)->create();

    expect(RefreshTokens::prune())->toBe(1)
        ->and(RefreshTokenModel::withTrashed()->find($old->id))->toBeNull()
        ->and($live->fresh())->not->toBeNull();
});

it('serves the same API through the injected manager', function (): void {
    $manager = app(RefreshTokensManager::class);
    $user = User::factory()->create();

    $issued = $manager->for($user)->withIp('198.51.100.7')->issue();

    expect($manager)->toBe(RefreshTokens::getFacadeRoot())
        ->and($manager->sessions($user)->all())->toHaveCount(1)
        ->and($manager->redeem($issued->plainText)?->user->is($user))->toBeTrue()
        ->and($manager->sessions($user)->all())->toBeEmpty();
});

it('resolves sub-accessor actions from the container, so host overrides apply', function (): void {
    $user = User::factory()->create();

    $this->app->bind(ListSessionsAction::class, fn (): object => new class
    {
        /** @return Collection<int, string> */
        public function execute(): Collection
        {
            return collect(['overridden']);
        }
    });

    expect(RefreshTokens::sessions($user)->all()->all())->toBe(['overridden']);
});
