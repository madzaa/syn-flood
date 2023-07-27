package main

import (
	"log"
	"os"
	"time"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type PacketHeader struct {
	Timestamp       uint32
	TimestampU      uint32
	CapturedPackets uint32
	UntrucPackets   uint32
}

func main() {
	dat, err := os.ReadFile("synflood.pcap")
	check(err)

	majorVersion := le(dat[4:6])
	minorVersion := le(dat[6:8])
	magicNumber := be(dat[:4])
	log.Printf("version %d.%d", majorVersion, minorVersion)
	log.Printf("version %x", magicNumber)

	var bytes uint32 = 24
	counter := 0

	for {
		if uint32(len(dat)-1) < bytes {
			break
		}

		header := PacketHeader{
			Timestamp:       le(getUint32(dat, bytes)),
			TimestampU:      le(getUint32(dat, bytes+4)),
			CapturedPackets: le(getUint32(dat, bytes+8)),
			UntrucPackets:   le(getUint32(dat, bytes+12)),
		}
		log.Printf("Timestamp: %s Captured Packets 0x%X, Untruncated Packets 0x%X", time.Unix(int64(header.Timestamp), 0), header.CapturedPackets, header.UntrucPackets)

		bytes += header.CapturedPackets + 16
		counter++
	}
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
