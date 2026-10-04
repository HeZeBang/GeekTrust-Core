// Command geektrustcore builds libgeektrust: the C ABI in docs/ABI.md over the
// data plane in internal/. It is a shared library, not a program — main does
// nothing — so it must be built with `-buildmode=c-shared`, which is what
// build.sh does for linux/amd64 and openharmony/arm64.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"

	"geektrust/internal/core"
)

// engine is the single library instance the ABI addresses.
var engine = core.New()

// versionCString is allocated once and never freed: geektrust_version hands
// out a static string the caller must not own or free (docs/ABI.md).
var versionCString = C.CString(core.Provenance())

//export geektrust_version
func geektrust_version() *C.char { return versionCString }

//export geektrust_init
func geektrust_init(sessionJSON *C.char, policyJSON *C.char, err *C.char, errLen C.int) (ret C.int) {
	defer recoverInto(&ret, err, errLen)
	clearErr(err, errLen)
	if initErr := engine.Init(goString(sessionJSON), goString(policyJSON)); initErr != nil {
		writeErr(err, errLen, initErr.Error())
		return 1
	}
	return 0
}

//export geektrust_start_proxies
func geektrust_start_proxies(socksAddr *C.char, httpAddr *C.char, err *C.char, errLen C.int) (ret C.int) {
	defer recoverInto(&ret, err, errLen)
	clearErr(err, errLen)
	if startErr := engine.StartProxies(goString(socksAddr), goString(httpAddr)); startErr != nil {
		writeErr(err, errLen, startErr.Error())
		return 1
	}
	return 0
}

//export geektrust_attach_tun_fd
func geektrust_attach_tun_fd(fd C.int, err *C.char, errLen C.int) (ret C.int) {
	defer recoverInto(&ret, err, errLen)
	clearErr(err, errLen)
	if attachErr := engine.AttachTunFD(int(fd)); attachErr != nil {
		writeErr(err, errLen, attachErr.Error())
		return 1
	}
	return 0
}

//export geektrust_status
func geektrust_status(outJSON *C.char, outJSONLen C.int) (ret C.int) {
	defer recoverInto(&ret, nil, 0)
	snapshot, statusErr := engine.Status()
	if statusErr != nil {
		// The ABI gives status no error buffer; a failure is the return code.
		clearErr(outJSON, outJSONLen)
		return 1
	}
	return writeString(outJSON, outJSONLen, snapshot)
}

//export geektrust_close
func geektrust_close() {
	// The ABI gives close no error buffer, but a C caller must still never see
	// a crash: report and swallow.
	defer recoverInto(nil, nil, 0)
	engine.Close()
}

func main() {}

// goString reads a borrowed C string. A careless caller may pass NULL; that is
// an empty payload, not a crash.
func goString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

// clearErr empties the caller's error buffer so a stale message can never be
// mistaken for the outcome of this call.
func clearErr(err *C.char, errLen C.int) { writeString(err, errLen, nil) }

// writeErr copies msg into the caller's buffer as UTF-8, truncated to fit and
// always NUL-terminated.
func writeErr(err *C.char, errLen C.int, msg string) {
	writeString(err, errLen, []byte(msg))
}

// writeString writes data into buf as a NUL-terminated C string, within bounds
// even when that truncates it, and reports whether all of it fit.
func writeString(buf *C.char, bufLen C.int, data []byte) C.int {
	if buf == nil || bufLen < 1 {
		return 1
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	limit := len(dst) - 1
	n := len(data)
	truncated := C.int(0)
	if n > limit {
		n, truncated = limit, 1
	}
	copy(dst[:n], data[:n])
	dst[n] = 0
	return truncated
}

// recoverInto turns a panic into the ABI's failure shape: a non-zero return
// and the panic in the error buffer. Functions without a buffer keep only the
// non-zero part — the point is that a panic never crosses back into C.
func recoverInto(ret *C.int, err *C.char, errLen C.int) {
	recovered := recover()
	if recovered == nil {
		return
	}
	writeErr(err, errLen, fmt.Sprintf("geektrust: internal panic: %v", recovered))
	if ret != nil {
		*ret = 1
	}
}
