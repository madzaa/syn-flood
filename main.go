package main

import (
	"log"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type PacketHeader struct {
	Timestamp          uint32
	TimestampU         uint32
	CapturedPackets    uint32
	UntruncatedPackets uint32
}

func main() {
	dat, err := os.ReadFile("synflood.pcap")
	check(err)

	getHeader(dat)

	log.Printf("%d", parsePacketHeaders(dat))
}

func parsePacketHeaders(dat []byte) int {
	var bytes uint32 = 24
	counter := 0

	for {
		if uint32(len(dat)-1) < bytes {
			break
		}

		header := PacketHeader{
			Timestamp:          le(getUint32(dat, bytes)),
			TimestampU:         le(getUint32(dat, bytes+4)),
			CapturedPackets:    le(getUint32(dat, bytes+8)),
			UntruncatedPackets: le(getUint32(dat, bytes+12)),
		}

		bytes += header.CapturedPackets + 16
		counter++
	}
	return counter
}

func getHeader(dat []byte) (int, int, int) {
	if len(dat) < 8 {
		panic("Header is too short")
	}
	magicNumber := le(dat[:4])
	majorVersion := le(dat[4:6])
	minorVersion := le(dat[6:8])
	return int(magicNumber), int(majorVersion), int(minorVersion)
}

func getUint32(dat []byte, bytes uint32) []byte {
	return dat[bytes : bytes+4]
}

func le(bytes []byte) uint32 {
	var integer uint32 = 0
	for i, b := range bytes {
		integer |= uint32(b) << (i * 8)
	}
	return integer
}

func be(bytes []byte) int {
	var integer = 0
	for i, b := range bytes {
		shift := len(bytes) - i - 1
		integer |= int(b) << (shift * 8)
	}
	return integer
}
