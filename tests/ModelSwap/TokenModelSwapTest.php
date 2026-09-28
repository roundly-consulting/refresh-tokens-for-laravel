<?php

declare(strict_types=1);

use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\CustomRefreshToken;
use RoundlyConsulting\RefreshTokens\Tests\Fixtures\User;

/**
 * S — the model-swap proof, with `refresh-tokens.model` swapped BEFORE boot.
 *
 * The package's own swap tests (tests/Configured) set the config in a `beforeEach`, i.e.
 * after the providers booted and after the migrations ran. They are kept — they cover the
 * seam broadly — but they are structurally unable to see a boot-time or migration-time
 * bug, because a real host sets this key in `config/refresh-tokens.php`, before anything
 * boots. These cases close that gap.
 *
 * `toHonourModelSwap` fails fast if the config does not already name the subclass (i.e. if
 * the before-boot swap was forgotten), then asserts every returned model's **concrete
 * class** — `instanceof` is not enough, because a row created as the packaged class never
 * fires the host's model events — and finally that a `created` event landed on the
 * subclass itself, the only proof the row was really created AS the host's class
 * (permissions #31, where a `findOrCreate` helper's `static::query()` broke authorization).
 */
it('issues through the configured model when it is swapped before boot', function (): void {
    $user = User::factory()->create();

    expect('refresh-tokens.model')->toHonourModelSwap(CustomRefreshToken::class, function () use ($user): array {
        // The real issuing flow, not a resolver string check.
        $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

        return [
            $new->token,
            // Every read-back seam a host would touch must land on the same class.
            RefreshTokens::sessions($user)->all()->first(),
            $user->refreshTokens()->first(),
            $user->sessions()->first(),
        ];
    });
});

/**
 * Redemption is the read side of the seam: it looks a token up BY DIGEST across the whole
 * table and hands the row back. That lookup is where a `static::query()`/`self::query()`
 * bypass hides (permissions #31/#34, jwt #5) — a row hydrated as the packaged base class
 * would skip the host's model events entirely while still passing an `instanceof` check.
 *
 * `expectsCreation: false` is deliberate and states a real fact about this package:
 * `redeem()` creates nothing. It revokes the presented row and hands it back
 * (`RedemptionResult::$redeemedToken`); minting the replacement is the host's own
 * `issue(..., familyId:)` call, covered by the case above. Saying so explicitly is
 * required — the created-event half used to be skipped silently when a flow made no row,
 * which quietly turned 15 assertions into 13 under the same name.
 */
it('redeems through the configured model when it is swapped before boot', function (): void {
    $user = User::factory()->create();
    $new = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    expect('refresh-tokens.model')->toHonourModelSwap(
        CustomRefreshToken::class,
        function () use ($new): array {
            $result = RefreshTokens::redeem($new->plainText);

            expect($result)->not->toBeNull();

            return [$result->redeemedToken];
        },
        expectsCreation: false,
    );
});

/**
 * The rotated replacement — a row minted into an EXISTING family, which is the flow a host
 * runs on every refresh. It must be created as the host's class, not merely returned as it.
 */
it('mints a rotated replacement into the family as the configured model', function (): void {
    $user = User::factory()->create();
    $first = RefreshTokens::issue($user, new IssueContext(accessReference: 'acc-a'));

    $result = RefreshTokens::redeem($first->plainText);

    expect($result)->not->toBeNull();

    expect('refresh-tokens.model')->toHonourModelSwap(CustomRefreshToken::class, function () use ($user, $result): array {
        $replacement = RefreshTokens::issue($user, new IssueContext(
            accessReference: 'acc-b',
            familyId: $result->familyId,
        ));

        return [$replacement->token];
    });
});
