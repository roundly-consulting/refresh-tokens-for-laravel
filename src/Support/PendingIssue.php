<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use RoundlyConsulting\RefreshTokens\Contracts\RefreshTokenManager;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use SensitiveParameter;

/**
 * Fluent sugar over {@see IssueContext} for the common controller case:
 * `RefreshToken::for($user)->fromRequest($request)->linkedTo($jti)->issue()`.
 */
final class PendingIssue
{
    private ?string $ipAddress = null;

    private ?string $userAgent = null;

    private ?string $accessReference = null;

    private ?string $familyId = null;

    public function __construct(
        private readonly RefreshTokenManager $manager,
        private readonly Authenticatable $user,
    ) {}

    public function fromRequest(Request $request): self
    {
        $this->ipAddress = $request->ip();
        $this->userAgent = $request->userAgent();

        return $this;
    }

    public function withIp(?string $ipAddress): self
    {
        $this->ipAddress = $ipAddress;

        return $this;
    }

    public function withUserAgent(?string $userAgent): self
    {
        $this->userAgent = $userAgent;

        return $this;
    }

    public function linkedTo(#[SensitiveParameter] ?string $accessReference): self
    {
        $this->accessReference = $accessReference;

        return $this;
    }

    public function inFamily(?string $familyId): self
    {
        $this->familyId = $familyId;

        return $this;
    }

    public function issue(): NewRefreshToken
    {
        return $this->manager->issue($this->user, new IssueContext(
            ipAddress: $this->ipAddress,
            userAgent: $this->userAgent,
            accessReference: $this->accessReference,
            familyId: $this->familyId,
        ));
    }
}
