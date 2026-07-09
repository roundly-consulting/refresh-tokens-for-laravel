<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\Events\RefreshTokenIssued;
use RoundlyConsulting\RefreshTokens\Support\TokenHasher;
use RoundlyConsulting\RefreshTokens\Support\TokenModel;

/**
 * Mint a new opaque refresh token: generate a high-entropy plaintext, store only
 * its hash, root or inherit a family lineage, and return the plaintext once.
 */
final class IssueRefreshTokenAction
{
    public function __construct(
        private readonly TokenHasher $hasher,
    ) {}

    public function execute(Authenticatable $user, IssueContext $context): NewRefreshToken
    {
        $plain = $this->hasher->generate();

        $token = TokenModel::make();
        $token->setAttribute(TokenModel::foreignKey(), $user->getAuthIdentifier());
        $token->token_hash = $this->hasher->hash($plain);
        $token->family_id = $context->familyId ?? (string) Str::uuid();
        $token->access_reference = $context->accessReference;
        $token->ip_address = $context->ipAddress;
        $token->user_agent = $context->userAgent;
        $token->expires_at = CarbonImmutable::now()->addSeconds($this->ttl());
        $token->save();

        Event::dispatch(new RefreshTokenIssued($token->getKey()));

        return new NewRefreshToken($plain, $token);
    }

    private function ttl(): int
    {
        $ttl = config('refresh-tokens.ttl', 2_592_000);

        return is_int($ttl) && $ttl > 0 ? $ttl : 2_592_000;
    }
}
