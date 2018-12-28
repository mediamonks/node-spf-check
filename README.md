# ✉️  spf-check [![Build Status](https://travis-ci.org/mediamonks/node-spf-check.svg)](https://travis-ci.org/mediamonks/node-spf-check) [![Coverage Status](https://coveralls.io/repos/github/mediamonks/node-spf-check/badge.svg)](https://coveralls.io/github/mediamonks/node-spf-check)

[RFC4408]: https://tools.ietf.org/html/rfc4408
[RFC4408-2.5]: https://tools.ietf.org/html/rfc4408#section-2.5

Implements [RFC4408] Sender Policy Framework (SPF) `check_host()` validation.

## Install

    yarn add spf-check

## Usage

The stable API returns a string with one of the [possible returns][RFC4408-2.5].

```js
const spf = require('spf-check');
const result = spf(ip, domain, sender);

if (result === spf.Pass) {
    // Yay!
}
```

## API

This module also exports `SPF` and `SPFResult` classes to allow inspect the
result and read the expected message.

```js
const validator = new spf.SPF('mediamonks.com', 'info@mediamonks.com');
const result = validator.check('185.16.22.2');

assert(result instanceof spf.SPFResult);

if (result.result !== spf.Pass || result.result !== spf.Neutral) {
    console.error(result.message);
}
```

## License

MIT © [MediaMonks](https://www.mediamonks.com/)
