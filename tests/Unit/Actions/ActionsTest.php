<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\Actions\IssueRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\PruneRefreshTokensAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\Actions\RevokeSessionAction;
use RoundlyConsulting\RefreshTokens\Actions\RotateRefreshTokenAction;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Enums\RevocationReason;
use RoundlyConsulting\RefreshTokens\Exceptions\InvalidTokenConfigurationException;
use RoundlyConsulting\RefreshTokens\Exceptions\SessionNotFoundException;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\Client;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

function issueFor(User $user, ?IssueContext $context = null): NewRefreshToken
{
    return app(IssueRefreshTokenAction::class)->execute($user, $context ?? new IssueContext);
}

it('rotates into the same family through the action form', function (): void {
    $user = User::factory()->create();
    $issued = issueFor($user);

    $rotated = app(RotateRefreshTokenAction::class)->execute($issued->plainText, new RotationContext(ipAddress: '10.0.0.2', meta: ['k' => 'v']));

    expect($rotated?->user->is($user))->toBeTrue()
        ->and($rotated?->redeemedFamilyId)->toBe($issued->token->family_id)
        ->and($rotated?->newRefreshToken->token->family_id)->toBe($issued->token->family_id)
        ->and($rotated?->newRefreshToken->token->ip_address)->toBe('10.0.0.2')
        ->and($rotated?->newRefreshToken->token->meta)->toBe(['k' => 'v'])
        ->and($issued->token->fresh()?->revoked_reason)->toBe(RevocationReason::Rotated);
});

it('rotates nothing for an unknown token or another owner type', function (): void {
    $user = User::factory()->create();
    $issued = issueFor($user);

    expect(app(RotateRefreshTokenAction::class)->execute('never-issued'))->toBeNull()
        ->and(app(RotateRefreshTokenAction::class)->execute($issued->plainText, new RotationContext(ownerType: (new Client)->getMorphClass())))->toBeNull()
        ->and($issued->token->fresh()?->revoked_at)->toBeNull();
});

it('revokes by plaintext through the action form', function (): void {
    $user = User::factory()->create();
    $issued = issueFor($user);

    expect(app(RevokeRefreshTokenAction::class)->execute($issued->plainText, RevocationReason::Security))->toBeTrue()
        ->and(app(RevokeRefreshTokenAction::class)->execute($issued->plainText))->toBeFalse()
        ->and(app(RevokeRefreshTokenAction::class)->execute('never-issued'))->toBeFalse()
        ->and($issued->token->fresh()?->revoked_reason)->toBe(RevocationReason::Security);
});

it('revokes a session row by key and refuses an unknown key', function (): void {
    $user = User::factory()->create();
    $issued = issueFor($user);

    expect(app(RevokeSessionAction::class)->execute($issued->token->getKey()))->toBeTrue()
        ->and($issued->token->fresh()?->revoked_reason)->toBe(RevocationReason::Manual)
        ->and(fn () => app(RevokeSessionAction::class)->execute('404'))->toThrow(SessionNotFoundException::class, '[404]');
});

it('prunes past an explicit window and keeps rows inside it', function (): void {
    $user = User::factory()->create();
    $old = RefreshTokenModel::factory()->forOwner($user)->create(['revoked_at' => now()->subDays(3), 'revoked_reason' => RevocationReason::Logout]);
    $recent = RefreshTokenModel::factory()->forOwner($user)->create(['revoked_at' => now()->subHours(2), 'revoked_reason' => RevocationReason::Logout]);
    $expired = RefreshTokenModel::factory()->forOwner($user)->create(['expires_at' => now()->subDays(5)]);

    expect(app(PruneRefreshTokensAction::class)->execute(2))->toBe(2)
        ->and(RefreshTokenModel::withTrashed()->find($old->id))->toBeNull()
        ->and(RefreshTokenModel::withTrashed()->find($expired->id))->toBeNull()
        ->and($recent->fresh())->not->toBeNull();
});

it('refuses an explicit prune window under one day', function (int $days): void {
    expect(fn () => app(PruneRefreshTokensAction::class)->execute($days))
        ->toThrow(InvalidTokenConfigurationException::class, 'at least 1 day(s)');
})->with([0, -3]);

it('clamps a configured prune window to one day and tolerates a non-int', function (mixed $configured, int $expected): void {
    config()->set('refresh-tokens.prune.after', $configured);
    $user = User::factory()->create();

    RefreshTokenModel::factory()->forOwner($user)->create(['revoked_at' => now()->subHours(12), 'revoked_reason' => RevocationReason::Logout]);
    RefreshTokenModel::factory()->forOwner($user)->create(['revoked_at' => now()->subDays(2), 'revoked_reason' => RevocationReason::Logout]);
    RefreshTokenModel::factory()->forOwner($user)->create(['revoked_at' => now()->subDays(40), 'revoked_reason' => RevocationReason::Logout]);

    expect(app(PruneRefreshTokensAction::class)->execute())->toBe($expected);
})->with([
    'zero clamps to one day' => [0, 2],
    'negative clamps to one day' => [-40, 2],
    'numeric string reads as days' => ['1', 2],
    'non-int falls back to 30' => ['soon', 1],
]);
