# Agent Guide — `tinywasm/filetype`

Constraints for agents working on this library. Read this before any change.

---

## Scope — single responsibility

This library answers **one** question: *what is this file, judged only by its bytes — and do
we accept it?*

It does **not** read files, resolve paths, handle uploads, or store anything. If you are
tempted to add an `io.Reader` helper, a path utility or a size limit, **stop**: that belongs
to the caller. The name is `filetype`, not `file`, precisely so this stays closed.

## The two rules that are the reason this package exists

**1. Never decode. Ever.** Detection is a comparison of magic-byte prefixes and nothing else.
Decoding a PNG merely to "check it is valid" would pull in `image/png` + `compress/zlib` —
hundreds of KB in a WASM binary. That trade is never worth it. The same goes for
`net/http.DetectContentType` (standard library, and it sniffs into HTML/text types we
deliberately refuse) and any MIME library.

**2. The client's claim is not evidence.** A `Content-Type` header and a file extension are
text the client chose. Only the bytes decide. Any API that lets a caller pass in a claimed
type and have it trusted is a bug.

## Isomorphic — no build tags, no standard library

The same code runs in a browser (validating **before** upload) and on a server (validating
what arrived), so client and server can never disagree about what a file is. That property is
the whole point, and it breaks the moment someone adds a build tag or a stdlib import.

- **No standard library.** Errors use `tinywasm/fmt`. Byte helpers are written by hand here
  (`hasPrefix`, `hasPrefixFold`) rather than importing `bytes`.
- **One dependency:** `tinywasm/fmt`. Do not add a second one.

## Scriptable types are detected, never allowed

`SVG` and `HTML` are recognized **on purpose**, so a rejection can name them instead of
reporting a useless "unknown". Both can carry JavaScript: served from your own domain they
execute **in your origin**. They must never appear in an `Allowlist` for user uploads. The
`Images` allowlist exists as the safe default.

`Allowlist`'s zero value accepts **nothing** — a policy someone forgot to configure must not
be permissive.

## Testing

```bash
go install github.com/tinywasm/devflow/cmd/gotest@latest
gotest
```

- `gotest`, never `go test`. Stdlib assertions only. Tests live in `tests/`.
- Every new signature needs a **truncated-input** case (2 bytes, 1 byte, empty): a hostile
  client sends short input on purpose, and a bounds panic in a Worker is a crash.
- Publish with `gopush 'message'`.

## Documentation First

Update docs **before** code and before `gopush`: keep `README.md` in sync with the public
surface.
