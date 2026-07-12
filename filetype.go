// Package filetype identifies a file's real type from its leading bytes.
//
// It NEVER decodes content. Detection is a comparison of magic-byte prefixes, so the
// package costs almost nothing in a WASM binary — decoding a PNG merely to validate it
// would pull in image/png and compress/zlib, hundreds of KB.
//
// Isomorphic: no build tags, no standard library. The same detection runs in a browser
// (validating before upload) and on a server (validating what arrived), so client and
// server can never disagree about what a file is.
//
// The type a client declares — a Content-Type header, a file extension — is a claim, not
// evidence. Only the bytes are evidence.
package filetype

import "github.com/tinywasm/fmt"

// Type is a recognized file type: its real MIME type and canonical extension.
type Type struct {
	MIME string // "image/png"
	Ext  string // ".png"
	name string // "PNG" — for diagnostics
}

// The types this package recognizes.
//
// SVG and HTML are detected ON PURPOSE, so they can be rejected by name instead of
// vanishing into "unknown". Both can carry JavaScript: served from your own domain, they
// execute in your origin. Never put them in an Allowlist for user uploads.
var (
	PNG  = Type{MIME: "image/png", Ext: ".png", name: "PNG"}
	JPEG = Type{MIME: "image/jpeg", Ext: ".jpg", name: "JPEG"}
	GIF  = Type{MIME: "image/gif", Ext: ".gif", name: "GIF"}
	WebP = Type{MIME: "image/webp", Ext: ".webp", name: "WebP"}
	PDF  = Type{MIME: "application/pdf", Ext: ".pdf", name: "PDF"}

	SVG  = Type{MIME: "image/svg+xml", Ext: ".svg", name: "SVG"}
	HTML = Type{MIME: "text/html", Ext: ".html", name: "HTML"}
)

// Images is the safe default for user uploads: raster images only, nothing scriptable.
var Images = NewAllowlist(PNG, JPEG, GIF, WebP)

// String returns the type's short name ("PNG"), for diagnostics.
func (t Type) String() string {
	if t.name == "" {
		return "unknown"
	}
	return t.name
}

// Scriptable reports whether the type can carry executable code. Serving a scriptable
// file from your own domain runs that code in your origin.
func (t Type) Scriptable() bool {
	return t.name == SVG.name || t.name == HTML.name
}

// Detect returns the type deduced from data's leading bytes.
// ok=false means no known signature matched — the caller must reject the content, and
// never fall back to what the client claimed.
func Detect(data []byte) (t Type, ok bool) {
	switch {
	case hasPrefix(data, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return PNG, true
	case hasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return JPEG, true
	case hasPrefix(data, []byte("GIF87a")), hasPrefix(data, []byte("GIF89a")):
		return GIF, true
	case hasPrefix(data, []byte("RIFF")) && hasPrefixAt(data, 8, []byte("WEBP")):
		return WebP, true
	case hasPrefix(data, []byte("%PDF-")):
		return PDF, true
	}

	// Text-based formats: skip leading whitespace, then match case-insensitively.
	if rest := skipSpace(data); len(rest) > 0 {
		switch {
		case hasPrefixFold(rest, []byte("<svg")):
			return SVG, true
		case hasPrefixFold(rest, []byte("<!doctype html")), hasPrefixFold(rest, []byte("<html")):
			return HTML, true
		case hasPrefixFold(rest, []byte("<?xml")):
			// An XML declaration is how an SVG usually starts. Report SVG: the point is to
			// reject it, and calling it "unknown" would hide what it was.
			return SVG, true
		}
	}

	return Type{}, false
}

// Allowlist is the upload policy: which types this site accepts.
// The zero value accepts nothing — a policy you forgot to configure must not be permissive.
type Allowlist struct {
	allowed []Type
}

// NewAllowlist builds a policy accepting exactly the given types.
func NewAllowlist(t ...Type) Allowlist {
	return Allowlist{allowed: t}
}

// Validate detects data's type and checks it against the policy.
// The error names the type actually found, so a rejection is diagnosable.
func (a Allowlist) Validate(data []byte) (Type, error) {
	t, ok := Detect(data)
	if !ok {
		return Type{}, fmt.Err("filetype: unrecognized content - no known signature")
	}
	for _, allowed := range a.allowed {
		if allowed.name == t.name {
			return t, nil
		}
	}
	return Type{}, fmt.Err("filetype:", t.name, "is not allowed")
}

func hasPrefix(data, prefix []byte) bool {
	return hasPrefixAt(data, 0, prefix)
}

func hasPrefixAt(data []byte, offset int, prefix []byte) bool {
	if len(data) < offset+len(prefix) {
		return false
	}
	for i, b := range prefix {
		if data[offset+i] != b {
			return false
		}
	}
	return true
}

// hasPrefixFold compares ASCII case-insensitively. prefix must be lowercase.
func hasPrefixFold(data, prefix []byte) bool {
	if len(data) < len(prefix) {
		return false
	}
	for i, b := range prefix {
		if lower(data[i]) != b {
			return false
		}
	}
	return true
}

func lower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func skipSpace(data []byte) []byte {
	for i, b := range data {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return data[i:]
		}
	}
	return nil
}
