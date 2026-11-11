---
PLAN: "feat: filetype recognizes the common business media — video, audio and the safe document policies, still from the bytes"
TAG: v0.1.0
EXECUTOR: jules
REVIEWER: none
---

> Read AGENTS.md at the repo root before any change.
> **Finish by yourself:** when the delivery check passes, commit, push and open the pull request. Never ask whether to
> proceed or finalize — nobody answers, and a session that waits ends without your work. Commit after every stage.
> Never run `git reset`, `git restore`, `git checkout -- <file>` or `git stash` on your own work.
> **Publishing:** you publish only by OPENING THE PULL REQUEST (a `git push` from your sandbox does not reach GitHub). Open it after Stage 1 with whatever compiles and keep committing to it.
> **Never ask a yes/no question about progress**; ask only when a signature in this plan is wrong, and name the symbol.
> **Before you submit:** `git status` must be clean and `git diff --stat main` must list the files of the stages. A pull request that carries only go.mod, go.sum or docs/PLAN.md is a failed delivery: `git add -A`, commit and submit again.

# Plan: video, audio and document types in `filetype`

## Why (read once)

File upload (design D46) lets a business attach photos, scans, receipts and recordings to its records, each declared with a typed field (`input.ImageFile`, `input.VideoFile`…). The type always comes from the bytes (`Detect`), never from the client. Today `filetype` knows images and PDF only. This plan adds the common media types and the allowlists the fields use. Nothing else changes: the existing types, `Detect` for them, `Allowlist` and `Images` stay exactly as they are.

## Ecosystem search

Searched `Detect`, `Allowlist`, `magic`, `signature` over `webtyp`: `filetype` is the only place that reads a type from bytes (`cloudflare/files` and `input.File` call it). **Extend** it here; no other repo gets a copy.

## Design gate

1. **Prior art:** Linux `file`/libmagic signature database, Go `net/http.DetectContentType` (WHATWG MIME sniffing: MP4 by the `ftyp` box, WebM by the EBML header, MP3 by `ID3` or a frame sync, WAV by `RIFF…WAVE`, OGG by `OggS`), the `h2non/filetype` Go library. https://mimesniff.spec.whatwg.org/ (unverified in this session: from memory). We differ on purpose: signatures only, no decoding, no stdlib, so the WASM cost stays minimal.
2. **Novice name:** `filetype.MP4`, `filetype.WebM`, `filetype.Videos`, `filetype.Audio`, `filetype.Documents`: the name of the thing.
3. **Ledger:** concepts +8 types +3 allowlists; files to touch to accept a video −N; ways to do the same: 0.
4. **Where:** `filetype` (one concern: what a file is, from its bytes).
5. **Deletes:** nothing (new capability).

## Tools

```bash
go install webtyp.com/devflow/cmd/gotest@latest
```
No new dependency (`webtyp.com/fmt` only), no `replace`. If a module cannot be fetched, stop and say so in the PR.

## Stage 1 — the types and their signatures (`filetype.go`)

Next to `PNG`… add (same `Type{MIME, Ext, name}` shape):

```go
	MP4  = Type{MIME: "video/mp4", Ext: ".mp4", name: "MP4"}
	MOV  = Type{MIME: "video/quicktime", Ext: ".mov", name: "MOV"}
	WebM = Type{MIME: "video/webm", Ext: ".webm", name: "WebM"}
	MP3  = Type{MIME: "audio/mpeg", Ext: ".mp3", name: "MP3"}
	WAV  = Type{MIME: "audio/wav", Ext: ".wav", name: "WAV"}
	OGG  = Type{MIME: "audio/ogg", Ext: ".ogg", name: "OGG"}
	M4A  = Type{MIME: "audio/mp4", Ext: ".m4a", name: "M4A"}
```

In `Detect`, inside the first `switch` (before the text-based part), add these cases, after the `WebP` case:

```go
	case hasPrefix(data, []byte{0x1A, 0x45, 0xDF, 0xA3}): // EBML header: WebM (Matroska containers are not told apart)
		return WebM, true
	case hasPrefixAt(data, 4, []byte("ftyp")) && hasPrefixAt(data, 8, []byte("qt  ")):
		return MOV, true
	case hasPrefixAt(data, 4, []byte("ftyp")) && hasPrefixAt(data, 8, []byte("M4A ")):
		return M4A, true
	case hasPrefixAt(data, 4, []byte("ftyp")): // every other ISO base media brand (isom, iso2, mp41, mp42, avc1, M4V …)
		return MP4, true
	case hasPrefix(data, []byte("RIFF")) && hasPrefixAt(data, 8, []byte("WAVE")):
		return WAV, true
	case hasPrefix(data, []byte("OggS")):
		return OGG, true
	case hasPrefix(data, []byte("ID3")), hasPrefix(data, []byte{0xFF, 0xFB}), hasPrefix(data, []byte{0xFF, 0xF3}), hasPrefix(data, []byte{0xFF, 0xF2}):
		return MP3, true
```

(The existing `RIFF`+`WEBP` case stays first: a WAV is `RIFF` + `WAVE`, a different offset-8 word.) `Scriptable()` stays false for all of them.

Allowlists, next to `Images`:

```go
// Videos is the safe default for video uploads.
var Videos = NewAllowlist(MP4, MOV, WebM)

// Audio is the safe default for audio uploads.
var Audio = NewAllowlist(MP3, WAV, OGG, M4A)

// Documents is the safe default for scans and receipts: raster images and PDF, nothing scriptable.
var Documents = NewAllowlist(PNG, JPEG, WebP, PDF)
```

Doc comment of the package: one line per new type family. Delete nothing.

## Stage 2 — tests (`tests/filetype_test.go`, one row each in `docs/TESTS.md`, `| [Name](../tests/filetype_test.go) | rule |`)

Sample bytes (each ends with two zero bytes): `mp4 := []byte{0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0}`; `mov := {0,0,0,0x14,'f','t','y','p','q','t',' ',' ',0,0}`; `m4a := {0,0,0,0x18,'f','t','y','p','M','4','A',' ',0,0}`; `webm := {0x1A,0x45,0xDF,0xA3,0,0}`; `mp3id3 := []byte("ID3\x04\x00\x00")`; `mp3sync := {0xFF,0xFB,0x90,0x00}`; `wav := []byte("RIFF\x24\x00\x00\x00WAVEfmt ")`; `ogg := []byte("OggS\x00\x02")`.

| Test | setup → call → expected |
|---|---|
| `TestDetect_Video` | `Detect(mp4)` → `MP4`; `Detect(mov)` → `MOV`; `Detect(webm)` → `WebM` |
| `TestDetect_Audio` | `Detect(mp3id3)` and `Detect(mp3sync)` → `MP3`; `Detect(wav)` → `WAV`; `Detect(ogg)` → `OGG`; `Detect(m4a)` → `M4A` |
| `TestDetect_WebPStillWebP` | `Detect([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "))` → `WebP` (not `WAV`) |
| `TestVideos_RejectsAudioAndImages` | `Videos.Validate(mp4)` ok; `Videos.Validate(mp3sync)` → error naming `MP3`; `Videos.Validate(pngBytes)` → error |
| `TestAudio_RejectsVideo` | `Audio.Validate(wav)` ok; `Audio.Validate(mp4)` → error naming `MP4` |
| `TestDocuments_AcceptsPDFAndImagesNotSVG` | `Documents.Validate(pdf)` ok (`[]byte("%PDF-1.7")`); `Documents.Validate(pngBytes)` ok; `Documents.Validate(svgBytes)` → error naming `SVG` |
| `TestNewTypes_NotScriptable` | every new type: `Scriptable()` is false |

## Stage 3 — documentation (English, `webtyp/*`)

`README.md` (≤150 lines): one line per new type family and the three new allowlists with a usage example (`filetype.Videos.Validate(data)`). `docs/ARCHITECTURE.md` if it exists: the same sentence; otherwise only the README. No other docs.

## Delivery check

`gotest` passes on every destination (the wasm one included); `docs/TESTS.md` has the 7 rows above; the pull request is open. A tree that does not compile or whose tests did not run is a failed delivery.
