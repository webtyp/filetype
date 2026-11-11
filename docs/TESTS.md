| Test | setup → call → expected |
|---|---|
| [TestDetect_Video](../tests/filetype_test.go) | `Detect(mp4)` → `MP4`; `Detect(mov)` → `MOV`; `Detect(webm)` → `WebM` |
| [TestDetect_Audio](../tests/filetype_test.go) | `Detect(mp3id3)` and `Detect(mp3sync)` → `MP3`; `Detect(wav)` → `WAV`; `Detect(ogg)` → `OGG`; `Detect(m4a)` → `M4A` |
| [TestDetect_WebPStillWebP](../tests/filetype_test.go) | `Detect([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "))` → `WebP` (not `WAV`) |
| [TestVideos_RejectsAudioAndImages](../tests/filetype_test.go) | `Videos.Validate(mp4)` ok; `Videos.Validate(mp3sync)` → error naming `MP3`; `Videos.Validate(pngBytes)` → error |
| [TestAudio_RejectsVideo](../tests/filetype_test.go) | `Audio.Validate(wav)` ok; `Audio.Validate(mp4)` → error naming `MP4` |
| [TestDocuments_AcceptsPDFAndImagesNotSVG](../tests/filetype_test.go) | `Documents.Validate(pdf)` ok (`[]byte("%PDF-1.7")`); `Documents.Validate(pngBytes)` ok; `Documents.Validate(svgBytes)` → error naming `SVG` |
| [TestNewTypes_NotScriptable](../tests/filetype_test.go) | every new type: `Scriptable()` is false |
| [TestDetect](../tests/filetype_test.go) | `Detect(png)` → `PNG`; `Detect(jpeg)` → `JPEG`; `Detect(gif87a)` → `GIF`; `Detect(gif89a)` → `GIF`; `Detect(webp)` → `WebP`; `Detect(pdf)` → `PDF`; `Detect(svg)` → `SVG`; `Detect(svg uppercase)` → `SVG`; `Detect(svg with leading space)` → `SVG`; `Detect(svg via xml decl)` → `SVG`; `Detect(html)` → `HTML`; `Detect(html bare tag)` → `HTML`; `Detect(unknown)` → `Type{}`; `Detect(empty)` → `Type{}`; `Detect(only whitespace)` → `Type{}`; `Detect(truncated png)` → `Type{}`; `Detect(truncated riff)` → `Type{}`; `Detect(single byte)` → `Type{}` |
| [TestDetectIgnoresClaimedType](../tests/filetype_test.go) | `Detect(html disguised as image)` → `HTML` |
| [TestAllowlistRejectsScriptable](../tests/filetype_test.go) | `Images.Validate(svg)` → error |
| [TestAllowlistNamesWhatItFound](../tests/filetype_test.go) | `Images.Validate(pdf)` → error naming `PDF` |
| [TestAllowlistAcceptsListedType](../tests/filetype_test.go) | `Images.Validate(png)` ok |
| [TestZeroAllowlistAcceptsNothing](../tests/filetype_test.go) | `empty.Validate(png)` → error |
| [TestUnknownIsRejected](../tests/filetype_test.go) | `Images.Validate(unknown)` → error |
