<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\DataTransferObjects;

use RoundlyConsulting\RefreshTokens\Models\RefreshToken;
use SensitiveParameter;

/**
 * The result of issuing a token. The `plainText` is the high-entropy secret to
 * return to the client exactly once — it is never persisted; only its SHA-256
 * hash is stored on the accompanying `token` row.
 */
final readonly class NewRefreshToken
{
    public function __construct(
        #[SensitiveParameter] public string $plainText,
        public RefreshToken $token,
    ) {}
}
