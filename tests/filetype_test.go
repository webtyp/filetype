package filetype_test

import (
	"testing"

	"webtyp.com/filetype"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want filetype.Type
		ok   bool
	}{
		{"png", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00}, filetype.PNG, true},
		{"jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00}, filetype.JPEG, true},
		{"gif87a", []byte("GIF87a...."), filetype.GIF, true},
		{"gif89a", []byte("GIF89a...."), filetype.GIF, true},
		{"webp", []byte("RIFF\x00\x00\x00\x00WEBPVP8 "), filetype.WebP, true},
		{"pdf", []byte("%PDF-1.7\n"), filetype.PDF, true},

		// Scriptable formats are detected on purpose, so they can be rejected by name.
		{"svg", []byte("<svg xmlns=\"http://www.w3.org/2000/svg\">"), filetype.SVG, true},
		{"svg uppercase", []byte("<SVG>"), filetype.SVG, true},
		{"svg with leading space", []byte("\n  <svg>"), filetype.SVG, true},
		{"svg via xml decl", []byte("<?xml version=\"1.0\"?><svg>"), filetype.SVG, true},
		{"html", []byte("<!DOCTYPE html><html>"), filetype.HTML, true},
		{"html bare tag", []byte("<html>"), filetype.HTML, true},

		// Nothing matched: the caller must reject, never trust the client's claim.
		{"unknown", []byte("just some text"), filetype.Type{}, false},
		{"empty", nil, filetype.Type{}, false},
		{"only whitespace", []byte("   \n\t"), filetype.Type{}, false},

		// Truncated input must not panic — a hostile client sends 2 bytes on purpose.
		{"truncated png", []byte{0x89, 'P'}, filetype.Type{}, false},
		{"truncated riff", []byte("RIFF"), filetype.Type{}, false},
		{"single byte", []byte{0xFF}, filetype.Type{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := filetype.Detect(tt.data)
			if ok != tt.ok {
				t.Fatalf("Detect() ok = %v, want %v", ok, tt.ok)
			}
			if got.MIME != tt.want.MIME {
				t.Errorf("Detect() = %q, want %q", got.MIME, tt.want.MIME)
			}
		})
	}
}

func TestDetect_Video(t *testing.T) {
	mp4 := []byte{0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0}
	mov := []byte{0, 0, 0, 0x14, 'f', 't', 'y', 'p', 'q', 't', ' ', ' ', 0, 0}
	webm := []byte{0x1A, 0x45, 0xDF, 0xA3, 0, 0}

	tests := []struct {
		name string
		data []byte
		want filetype.Type
	}{
		{"mp4", mp4, filetype.MP4},
		{"mov", mov, filetype.MOV},
		{"webm", webm, filetype.WebM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := filetype.Detect(tt.data)
			if !ok {
				t.Fatalf("Detect() ok = false, want true")
			}
			if got.MIME != tt.want.MIME {
				t.Errorf("Detect() = %q, want %q", got.MIME, tt.want.MIME)
			}
		})
	}
}

func TestDetect_Audio(t *testing.T) {
	mp3id3 := []byte("ID3\x04\x00\x00")
	mp3sync := []byte{0xFF, 0xFB, 0x90, 0x00}
	wav := []byte("RIFF\x24\x00\x00\x00WAVEfmt ")
	ogg := []byte("OggS\x00\x02")
	m4a := []byte{0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'M', '4', 'A', ' ', 0, 0}

	tests := []struct {
		name string
		data []byte
		want filetype.Type
	}{
		{"mp3 id3", mp3id3, filetype.MP3},
		{"mp3 sync", mp3sync, filetype.MP3},
		{"wav", wav, filetype.WAV},
		{"ogg", ogg, filetype.OGG},
		{"m4a", m4a, filetype.M4A},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := filetype.Detect(tt.data)
			if !ok {
				t.Fatalf("Detect() ok = false, want true")
			}
			if got.MIME != tt.want.MIME {
				t.Errorf("Detect() = %q, want %q", got.MIME, tt.want.MIME)
			}
		})
	}
}

func TestDetect_WebPStillWebP(t *testing.T) {
	got, ok := filetype.Detect([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "))
	if !ok || got.MIME != filetype.WebP.MIME {
		t.Fatalf("Detect() = %v, want WebP", got.MIME)
	}
}

func TestVideos_RejectsAudioAndImages(t *testing.T) {
	mp4 := []byte{0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0}
	if _, err := filetype.Videos.Validate(mp4); err != nil {
		t.Fatalf("Videos allowlist rejected a video: %v", err)
	}

	mp3sync := []byte{0xFF, 0xFB, 0x90, 0x00}
	if _, err := filetype.Videos.Validate(mp3sync); err == nil || !contains(err.Error(), "MP3") {
		t.Fatalf("Videos allowlist accepted audio or failed to name MP3, error: %v", err)
	}

	pngBytes := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if _, err := filetype.Videos.Validate(pngBytes); err == nil {
		t.Fatalf("Videos allowlist accepted an image")
	}
}

func TestAudio_RejectsVideo(t *testing.T) {
	wav := []byte("RIFF\x24\x00\x00\x00WAVEfmt ")
	if _, err := filetype.Audio.Validate(wav); err != nil {
		t.Fatalf("Audio allowlist rejected audio: %v", err)
	}

	mp4 := []byte{0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0}
	if _, err := filetype.Audio.Validate(mp4); err == nil || !contains(err.Error(), "MP4") {
		t.Fatalf("Audio allowlist accepted video or failed to name MP4, error: %v", err)
	}
}

func TestDocuments_AcceptsPDFAndImagesNotSVG(t *testing.T) {
	pdf := []byte("%PDF-1.7")
	if _, err := filetype.Documents.Validate(pdf); err != nil {
		t.Fatalf("Documents allowlist rejected PDF: %v", err)
	}

	pngBytes := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if _, err := filetype.Documents.Validate(pngBytes); err != nil {
		t.Fatalf("Documents allowlist rejected PNG: %v", err)
	}

	svgBytes := []byte("<svg xmlns=\"http://www.w3.org/2000/svg\">")
	if _, err := filetype.Documents.Validate(svgBytes); err == nil || !contains(err.Error(), "SVG") {
		t.Fatalf("Documents allowlist accepted SVG or failed to name SVG, error: %v", err)
	}
}

func TestNewTypes_NotScriptable(t *testing.T) {
	types := []filetype.Type{
		filetype.MP4, filetype.MOV, filetype.WebM,
		filetype.MP3, filetype.WAV, filetype.OGG, filetype.M4A,
	}

	for _, ty := range types {
		if ty.Scriptable() {
			t.Errorf("Type %s must not be scriptable", ty.MIME)
		}
	}
}

// A PNG signature is not enough: the bytes decide, and only the bytes.
func TestDetectIgnoresClaimedType(t *testing.T) {
	// HTML content that a client uploads claiming "image/png".
	html := []byte("<!DOCTYPE html><html><script>alert(1)</script></html>")

	got, ok := filetype.Detect(html)
	if !ok {
		t.Fatal("Detect() failed to recognize HTML disguised as an image")
	}
	if got.MIME != filetype.HTML.MIME {
		t.Fatalf("Detect() = %q, want %q — the client's claim must be irrelevant", got, filetype.HTML)
	}
	if !got.Scriptable() {
		t.Error("HTML must report Scriptable() = true: served from our origin, it runs there")
	}
}

func TestAllowlistRejectsScriptable(t *testing.T) {
	svg := []byte("<svg onload=\"alert(1)\"></svg>")

	if _, err := filetype.Images.Validate(svg); err == nil {
		t.Fatal("Images allowlist accepted an SVG — it can carry JavaScript and must be rejected")
	}
}

func TestAllowlistNamesWhatItFound(t *testing.T) {
	pdf := []byte("%PDF-1.7\n")

	_, err := filetype.Images.Validate(pdf)
	if err == nil {
		t.Fatal("Images allowlist accepted a PDF")
	}
	// The rejection must be diagnosable: it says what the content actually was.
	if !contains(err.Error(), "PDF") {
		t.Errorf("error %q does not name the detected type", err)
	}
}

func TestAllowlistAcceptsListedType(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}

	got, err := filetype.Images.Validate(png)
	if err != nil {
		t.Fatalf("Images allowlist rejected a PNG: %v", err)
	}
	if got.Ext != ".png" {
		t.Errorf("Ext = %q, want %q", got.Ext, ".png")
	}
}

// A policy nobody configured must not be permissive.
func TestZeroAllowlistAcceptsNothing(t *testing.T) {
	var empty filetype.Allowlist
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}

	if _, err := empty.Validate(png); err == nil {
		t.Fatal("the zero Allowlist accepted a file — an unconfigured policy must accept nothing")
	}
}

func TestUnknownIsRejected(t *testing.T) {
	if _, err := filetype.Images.Validate([]byte("not a file")); err == nil {
		t.Fatal("Validate accepted unrecognized content")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
