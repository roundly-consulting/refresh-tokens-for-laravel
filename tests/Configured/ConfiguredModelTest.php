<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Facades\RefreshToken;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\CustomRefreshToken;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/**
 * The `refresh-tokens.model` seam, exercised end to end against a host subclass.
 *
 * A seam honoured in some call sites and bypassed in others is worse than no seam
 * at all: Eloquent keys model events on the concrete class, so a bypassed call site
 * silently runs a host's listeners against the wrong model (or not at all).
 */
beforeEach(function (): void {
    config()->set('refresh-tokens.model', CustomRefreshToken::class);
});

it('issues, lists and relates through the configured model', function (): void {
    $user = User::factory()->create();

    $new = RefreshToken::issue($user, new IssueContext);

    expect($new->token)->toBeInstanceOf(CustomRefreshToken::class)
        ->and(RefreshToken::listFor($user)->first())->toBeInstanceOf(CustomRefreshToken::class)
        ->and($user->refreshTokens()->first())->toBeInstanceOf(CustomRefreshToken::class)
        ->and($user->sessions()->first())->toBeInstanceOf(CustomRefreshToken::class);
});

it('redeems and revokes through the configured model', function (): void {
    $user = User::factory()->create();
    $new = RefreshToken::issue($user, new IssueContext);

    $result = RefreshToken::redeem($new->plainText);

    expect($result)->not->toBeNull();

    $second = RefreshToken::issue($user, new IssueContext);
    RefreshToken::revoke($second->plainText);

    expect($second->token->fresh()->revoked_at)->not->toBeNull();
});

it('prunes through the configured model, not the packaged base class', function (): void {
    // `php artisan model:prune` calls prunable() on the model the host swapped in,
    // and force-deletes the instances that builder returns. If they came back as the
    // packaged base class, a host subclass's global scopes would be dropped and its
    // delete listeners would never fire (the seam-bypass shape of certificates #26
    // and media #35).
    expect((new CustomRefreshToken)->prunable()->getModel())->toBeInstanceOf(CustomRefreshToken::class);

    $pruned = [];
    Event::listen(
        'eloquent.forceDeleted: '.CustomRefreshToken::class,
        function (RefreshTokenModel $model) use (&$pruned): void {
            $pruned[] = $model::class;
        },
    );

    RefreshTokenModel::factory()->count(2)->create([
        'expires_at' => CarbonImmutable::now()->subDays(90),
        'revoked_at' => CarbonImmutable::now()->subDays(90),
    ]);

    $this->artisan('model:prune', ['--model' => CustomRefreshToken::class])->assertSuccessful();

    expect($pruned)->toBe([CustomRefreshToken::class, CustomRefreshToken::class])
        ->and(RefreshTokenModel::withTrashed()->count())->toBe(0);
});
