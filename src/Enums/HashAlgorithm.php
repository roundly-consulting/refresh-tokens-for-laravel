<?php

declare(strict_types=1);

namespace RoundlyConsulting\RefreshTokens\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The at-rest hashing algorithms the package allows. Restricting `hash.algo` to
 * this allowlist stops an env typo (e.g. `md5`, `crc32b`) silently weakening the
 * token store; every member is a fast, fixed-width SHA-2 digest that fits the
 * `token_hash` column.
 */
enum HashAlgorithm: string
{
    use Helpers;

    case Sha256 = 'sha256';
    case Sha384 = 'sha384';
    case Sha512 = 'sha512';
}
