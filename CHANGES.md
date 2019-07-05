# Changes for spf-check

All notable changes grouped by version.

## [0.4.2] 2019-07-05

 - Returns `PermError` when TXT is not in US-ASCII.

## [0.4.1] 2019-01-30

Match only IPs of the same kind.

## [0.4.0] 2019-01-15

Publish NPM package.

## [0.3.0] 2018-12-28

 - `BC-BREAK` Now DNS lookup limit is enforced as 10 maximum queries for mechanisms and 10 maximum queries for retrieving A record out of exchanges returned in the MX mechanism.
 - New option `{ maxDNS: 10 }` to change the DNS lookup limit.
 - `BC-BREAK` Domain and sender parameters has been moved from `SPF.check()` to `SPF.constructor()`. Stable API has no change.

## [0.2.0] 2018-12-25

 - `BC-BREAK` Now DNS queries will be performed at evaluation time. Previous checks that returned `TempFail` might now return another value on an early match. Old method can be re-activated with `{ prefetch: true }` options.
 - Now `SPFResult` contains the last `mechanism` matched (useful for Received-SPF header field "mechanism") and a list of all `matched` mechanisms in case that at least one "include" mechanism was processed.

## [0.1.0] 2018-12-24

Initial version.
