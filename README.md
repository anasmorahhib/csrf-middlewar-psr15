# PSR-15 Middleware

[![Coverage Status](https://coveralls.io/repos/github/anasmorahhib/csrf-middlewar-psr15/badge.svg?branch=main)](https://coveralls.io/github/anasmorahhib/csrf-middlewar-psr15?branch=main)

its code is a reimplementation of the depo:
[https://github.com/Grafikart/PSR15-CsrfMiddleware](https://github.com/Grafikart/PSR15-CsrfMiddleware)

This middleware checks every POST, PATCH, PUT and DELETE requests for a CSRF token.
Tokens are persisted using an ArrayAccess compatible Session and are generated on demand.

## Installation

```bash
composer require morahhib/csrf-middleware-psr15
```

## How to use it

```php
$middleware = new CsrfMiddleware($_SESSION, 200);
$app->pipe($middleware);

// Generate input
$input = "<input type=\"hidden\" name=\"{$middleware->getFormKey()}\" value=\"{$middleware->generateToken()}\"/>
```

Middleware is constructed with these parameters:

- session, **ArrayAccess|array**, used to store tokens
- limit, **int**, limits the amount of tokens the session is allowed to persist
- sessionKey, **string**
- formKey, **string**
