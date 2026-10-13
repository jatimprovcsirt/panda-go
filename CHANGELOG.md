# Changelog

## Read this before creating a tag

**For a Go module the tag *is* the version.** There is no version field in
`go.mod` to disagree with, so a tag is not a label on a release — it is the
release. `go get` resolves a version by asking the repository for a tag, and
nothing else can correct a wrong one.

That makes this file the only record of what has been published. Read it
before tagging.

1. **Read this file.** It records what has been released and what the next
   number is.
2. Tag with an immutable module path form: `v0.5.1`, never `0.5.1`.
3. Push the branch, then the tag.
4. Confirm the proxy can see it: `go list -m github.com/jatimprovcsirt/panda-go@v0.5.1`
5. Add it to the table below.

## Released

| Version | Date | What it was |
|---|---|---|
| `v0.5.1` | 2026-10-13 | The wizard compiled its own copy of the token pattern. No code defect found in this package — it was the one the other three were measured against. |
| `v0.5.0` | 2026-08-16 | CLI non-interactive mode documentation and linter fixes. |
| `v0.1.6` | 2026-08-14 | README corrected PANDA CLI workflow. |
| `v0.1.4` | 2026-08-14 | README corrected PANDA CLI workflow. |
| `v0.1.3` | 2026-08-13 | Vault AppRole auto-renewal and token TTL configuration. |
| `v0.1.2` | 2026-08-10 | PANDA portal URL added to documentation. |
| `v0.1.1` | 2026-07-18 | 48/64 hex token support. |
| `v0.1.0` | 2026-07-12 | First tag. |

## Why there are two version lines

The tags run `v0.1.0`–`v0.1.4`, then a jump to `v0.5.0`, with `v0.1.6` sitting
between `v0.1.4` and `v0.5.0` on the same day, 14 August.

`v0.1.6` is therefore *newer* than `v0.1.4` but *older* than `v0.5.0` — which
the numbers alone do not tell you. Nothing is broken, but a consumer pinning
`v0.1.6` is not on the tip of anything.

`v0.5.0` is the version to build on. If the numbering is re-based again, say so
here.

## A note on what this repository is for

`panda-docker` vendors this module. A tag pushed here reaches that service on
its next dependency update, so a tag is not purely a statement about this
repository.

## What v0.5.1 fixes

### The wizard had its own copy of the pattern

`crypto.TOKEN_PATTERN` has accepted 48 or 64 hex characters for a while. The
interactive wizard in `cmd/init.go` did not use it: it compiled its own regexp
with the pattern written out again, and that copy accepted 48 only. A token the
rest of the tool considers valid was rejected in exactly one place — the one a
user actually types into.

That copy is gone; the wizard calls `crypto.ValidateTokenFormat()`, a new
exported function that answers the same question without the portal call.

`cmd/init_test.go` had the same problem in the other direction: it compiled a
*correct* copy of the pattern and asserted against that, so it proved nothing
about `init` and would have gone on passing through the bug above. It now
asserts the function the wizard calls. `crypto/security_test.go` gets the same
treatment, against the package constant instead of a literal.

All packages pass.
