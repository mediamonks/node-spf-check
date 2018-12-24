# ✉️  spf-check

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
const validator = new spf.SPF();
const result = validator.check(ip, domain, sender);

result instanceof spf.SPFResult; // true

if (result.result !== spf.Pass || result.result !== spf.None) {
    console.log(result.message);
}
```

## License

MIT © [MediaMonks](https://www.mediamonks.com/)
