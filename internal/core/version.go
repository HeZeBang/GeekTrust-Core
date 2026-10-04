package core

// ABI is the compatibility integer of docs/ABI.md. The app compares it with
// its own constant at load time and refuses a library that disagrees, so it
// must be bumped for any change to a signature, a JSON field or the meaning of
// a return value.
const ABI = 1

// markerPrefix introduces the provenance marker the build embeds.
const markerPrefix = "TECHPIE-GEEKTRUST="

// provenance is the whole provenance marker:
//
//	TECHPIE-GEEKTRUST=<abi>:<version>:<source digest>
//
// build.sh computes it and substitutes it here through
// `-ldflags -X geektrust/internal/core.provenance=…`, so the marker — not its
// pieces — is a contiguous string in the library's read-only data. That is
// what the app's provenance check looks for: it recomputes the digest from the
// submodule tree it pinned and refuses an artifact built from other sources.
//
// The default is what a plain `go build`/`go test` produces; it claims no
// provenance, and build.sh keeps the abi field in step with ABI above.
var provenance = markerPrefix + "1:dev:unknown"

// Provenance returns the embedded marker.
func Provenance() string { return provenance }
