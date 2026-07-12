# tinywasm/filetype
<img src="docs/img/badges.svg">

Identifies a file's real type **from its bytes**. Never decodes, never trusts the client.

A `Content-Type` header and a file extension are text the client chose — a claim, not
evidence. Only the leading bytes decide.

```bash
go get github.com/tinywasm/filetype
```

## Why it is tiny

Detection is a comparison of magic-byte prefixes and nothing else. Decoding a PNG merely to
check that it is valid would pull in `image/png` + `compress/zlib` — hundreds of KB in a WASM
binary. This package refuses that trade, which is the whole reason it exists.

**Isomorphic:** no build tags, no standard library. The same detection runs in the browser
(validating *before* upload) and on the server (validating what arrived), so client and server
can never disagree about what a file is.

## Usage

```go
import "github.com/tinywasm/filetype"

// Images is the safe default: raster images only, nothing scriptable.
t, err := filetype.Images.Validate(data)
if err != nil {
    return err // "filetype: PDF is not allowed" — the error names what it actually found
}

key := id + t.Ext        // ".png" — the extension comes from the bytes, not from a filename
bucket.Put(key, data, t.MIME)
```

Or detect without a policy:

```go
t, ok := filetype.Detect(data)
if !ok {
    // No known signature. Reject — never fall back to what the client claimed.
}
```

## Recognized types

| Type | Detected | In `Images` |
|---|---|---|
| `PNG`, `JPEG`, `GIF`, `WebP` | ✅ | ✅ |
| `PDF` | ✅ | ❌ — add it explicitly if you want it |
| `SVG`, `HTML` | ✅ | ❌ **never** |

**SVG and HTML are detected on purpose, so they can be rejected *by name*** instead of
disappearing into "unknown". Both can carry JavaScript: served from your own domain, they
execute **in your origin**. `Type.Scriptable()` reports this.

Build your own policy with `NewAllowlist(...)`. Its **zero value accepts nothing** — a policy
someone forgot to configure must not be permissive.

## Testing

```bash
gotest
```

See [AGENTS.md](AGENTS.md) for the constraints that govern this library.
