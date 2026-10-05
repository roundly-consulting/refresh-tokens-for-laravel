<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/refresh-tokens-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=refresh-tokens-for-laravel">
    <img src="https://raw.githubusercontent.com/roundly-consulting/refresh-tokens-for-laravel/main/art/hero.png" alt="Refresh Tokens for Laravel — Roundly open source" width="100%">
  </a>
</p>
<!-- roundly-hero:end -->

<!-- roundly-badges:start -->
<p align="center">
  <a href="https://packagist.org/packages/roundly-consulting/refresh-tokens-for-laravel"><img src="https://img.shields.io/packagist/v/roundly-consulting/refresh-tokens-for-laravel?style=flat-square&label=release" alt="Latest release"></a>
  <a href="https://github.com/roundly-consulting/refresh-tokens-for-laravel/actions/workflows/run-tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/refresh-tokens-for-laravel/run-tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://github.com/roundly-consulting/refresh-tokens-for-laravel/actions/workflows/fix-php-code-style-issues.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/refresh-tokens-for-laravel/fix-php-code-style-issues.yml?branch=main&style=flat-square&label=code%20style" alt="Code style"></a>
  <a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/donate-support%20our%20open%20source-F24E29?style=flat-square&logo=stripe&logoColor=white" alt="Donate"></a>
  <a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/patreon-become%20a%20patron-F96854?style=flat-square&logo=patreon&logoColor=white" alt="Patreon"></a>
  <a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=refresh-tokens-for-laravel#crypto"><img src="https://img.shields.io/badge/crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=flat-square&logo=bitcoin&logoColor=white" alt="Crypto"></a>
</p>
<!-- roundly-badges:end -->

# Refresh Tokens for Laravel

Opaque, rotating refresh tokens and device sessions for Laravel — SHA-256 at rest, atomic
anti-double-spend rotation, and whole-family revocation the moment a spent token is replayed.
Tokens hang off a polymorphic owner, so any `Authenticatable` model can hold sessions; JWT minting,
user-agent parsing and routes stay in your app.

## Installation

Requires PHP 8.4 and Laravel 12 or 13.

```bash
composer require roundly-consulting/refresh-tokens-for-laravel
php artisan vendor:publish --tag="refresh-tokens-migrations"
php artisan migrate
```

If your owner models have UUID/ULID keys, set `REFRESH_TOKENS_KEY_TYPE=uuid` (or `ulid`)
**before** migrating.

## Usage

Add the trait to every model that holds sessions:

```php
use RoundlyConsulting\RefreshTokens\Traits\HasRefreshTokens;

final class User extends Authenticatable
{
    use HasRefreshTokens;
}
```

Mint your access token first, then issue a refresh token linked to it and rotate it on refresh:

```php
use RoundlyConsulting\RefreshTokens\DataTransferObjects\RotationContext;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;

$new = RefreshTokens::for($user)->fromRequest($request)->linkedTo($access->jti)->issue();
$new->plainText;                         // hand to the client ONCE — never stored

$rotation = RefreshTokens::rotate($new->plainText, new RotationContext(accessReference: $newAccess->jti));
$rotation->newRefreshToken->plainText;   // the replacement; a null result means "log in again"

RefreshTokens::rotate($new->plainText);  // null — a replayed token revokes the whole session
```

Manage device sessions:

```php
RefreshTokens::sessions($user)->all();                             // active sessions, newest first
RefreshTokens::sessions($user)->revokeAllExcept($currentFamilyId); // "log out my other devices"
RefreshTokens::revoke($plainFromClient);                           // logout with the token in hand
```

<!-- roundly-docs:start -->
## Documentation

The full documentation — configuration, every feature and its API, and testing — lives on our
website: **[roundly-consulting.com/open-source/docs/refresh-tokens-for-laravel](https://roundly-consulting.com/open-source/docs/refresh-tokens-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=refresh-tokens-for-laravel)**

Release notes are in [CHANGELOG.md](CHANGELOG.md). To contribute, see the
[contributing guide](https://github.com/roundly-consulting/.github/blob/main/CONTRIBUTING.md).
<!-- roundly-docs:end -->

<!-- roundly-support:start -->
## Support our work

This package is free and open source, built and maintained by
[Roundly Consulting](https://roundly-consulting.com/open-source?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=refresh-tokens-for-laravel).
If it saves you time, please consider supporting our open-source work — a one-time donation, a
monthly pledge on Patreon or a crypto donation helps fund maintenance, new features and new
packages.

<a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/Donate-Support%20Roundly%20open%20source-F24E29?style=for-the-badge&logo=stripe&logoColor=white" alt="Donate to Roundly open source"></a>
<a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/Patreon-Become%20a%20patron-F96854?style=for-the-badge&logo=patreon&logoColor=white" alt="Become a patron on Patreon"></a>
<a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=refresh-tokens-for-laravel#crypto"><img src="https://img.shields.io/badge/Crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate crypto: BTC, ETH, BNB or SOL"></a>
<!-- roundly-support:end -->

## License

The MIT License (MIT). Copyright (c) roundly-consulting. See [LICENSE.md](LICENSE.md).
