package l3

import (
	"encoding/binary"
	"testing"
)

func TestEchoValidation(t *testing.T) {
	packet := make([]byte, 31)
	packet[0], packet[8], packet[9], packet[20] = 0x45, 64, 1, 8
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	copy(packet[24:], []byte{1, 2, 0, 3, 4, 5, 6})
	fixChecksum(packet[:20], 10)
	fixChecksum(packet[20:], 2)
	if _, err := validateEcho(packet, 8); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[6] = 0x20 }, // fragmented
		func(p []byte) { p[9] = 17 },
		func(p []byte) { p[21] = 1 },
		func(p []byte) { p[30] ^= 1 },
		func(p []byte) { p[2] = 1 },
	} {
		p := append([]byte(nil), packet...)
		mutate(p)
		if _, err := validateEcho(p, 8); err == nil {
			t.Fatal("invalid Echo accepted")
		}
	}
	for n := 0; n < len(packet); n++ {
		if _, err := validateEcho(packet[:n], 8); err == nil {
			t.Fatal("truncated Echo accepted")
		}
	}
}
