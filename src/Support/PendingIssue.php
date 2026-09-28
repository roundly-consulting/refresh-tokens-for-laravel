<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\IssueContext;
use RoundlyConsulting\RefreshTokens\DataTransferObjects\NewRefreshToken;
use RoundlyConsulting\RefreshTokens\RefreshTokensManager;
use SensitiveParameter;

/**
 * Fluent sugar over {@see IssueContext} for the common controller case:
 * `RefreshTokens::for($owner)->fromRequest($request)->linkedTo($jti)->issue()`.
 * The terminal `issue()` goes through the manager, so `RefreshTokens::fake()` records it.
 */
final class PendingIssue
{
    private ?string $ipAddress = null;

    private ?string $userAgent = null;

    private ?string $accessReference = null;

    private ?string $familyId = null;

    private ?string $newFamilyId = null;

    private ?int $ttl = null;

    private ?int $absoluteTtl = null;

    /** @var array<string, mixed>|null */
    private ?array $meta = null;

    public function __construct(
        private readonly RefreshTokensManager $manager,
        private readonly Authenticatable&Model $owner,
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

    /**
     * Root a new family under a caller-chosen UUID (e.g. the session id already
     * minted into the access token).
     */
    public function startingFamily(string $uuid): self
    {
        $this->newFamilyId = $uuid;

        return $this;
    }

    /** Sliding lifetime for this token, in seconds (overrides `refresh-tokens.ttl`). */
    public function ttl(int $seconds): self
    {
        $this->ttl = $seconds;

        return $this;
    }

    /** Absolute session cap in seconds, honoured when rooting a family; 0 = uncapped. */
    public function absoluteTtl(int $seconds): self
    {
        $this->absoluteTtl = $seconds;

        return $this;
    }

    /**
     * Session metadata stored as JSON and inherited across rotation. Never secrets.
     *
     * @param  array<string, mixed>  $meta
     */
    public function meta(array $meta): self
    {
        $this->meta = $meta;

        return $this;
    }

    public function issue(): NewRefreshToken
    {
        return $this->manager->issue($this->owner, new IssueContext(
            ipAddress: $this->ipAddress,
            userAgent: $this->userAgent,
            accessReference: $this->accessReference,
            familyId: $this->familyId,
            newFamilyId: $this->newFamilyId,
            ttl: $this->ttl,
            absoluteTtl: $this->absoluteTtl,
            meta: $this->meta,
        ));
    }
}
