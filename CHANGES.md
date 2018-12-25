# Changes for spf-check

All notable changes grouped by version.

## [0.2.0] 2018-12-25

 - `BC-BREAK` Now DNS queries will be performed at evalution time. Previous checks that returned `TempFail` might now return another value on an early match. Old method can be re-activated with `{ prefetch: true }` options.
 - Now `SPFResult` contains the last `mechanism` matched (useful for Received-SPF header field "mechanism") and a list of all `matched` mechanisms in case that at least one "include" mechanism was processed.

## [0.1.0] 2018-12-24

Initial version.
