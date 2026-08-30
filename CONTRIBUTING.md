# Contributing

Changes must preserve the canonical repository and harness identifiers, pass
`make verify-offline`, and include an updated task packet when implementation
scope changes. Public-contract changes begin in `mas-harness-contracts` and are
consumed only through immutable prerelease versions and digests.

External fork pull requests are not executed automatically on self-hosted
runners. A maintainer must review and import the commit into a trusted branch.
