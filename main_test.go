package main

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

func Test_be(t *testing.T) {
	type args struct {
		bytes []byte
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{name: "Big endian 1", args: args{[]byte{0xd4, 0xc3, 0xb2, 0xa1}}, want: 0xD4C3B2A1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := be(tt.args.bytes); got != tt.want {
				t.Errorf("be() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_le(t *testing.T) {
	type args struct {
		bytes []byte
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
		{name: "Small endian 1", args: args{[]byte{0xD4, 0xC3, 0xB2, 0xA1}}, want: 0xA1B2C3D4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := le(tt.args.bytes); got != tt.want {
				t.Errorf("le() = %X, want %X", got, tt.want)
			}
		})
	}
}

func Test_getUint32(t *testing.T) {
	type args struct {
		dat   []byte
		bytes uint32
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
		{name: "Magic number", args: args{dat: []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00}, bytes: 0}, want: []byte{0xD4, 0xC3, 0xB2, 0xA1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getUint32(tt.args.dat, tt.args.bytes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getUint32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getHeader(t *testing.T) {
	type args struct {
		dat []byte
	}
	tests := []struct {
		name  string
		args  args
		want  int
		want1 int
		want2 int
		want3 error
	}{
		// TODO: Add test cases.
		{name: "Check magic number, major version and  minor version", args: args{dat: []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00}}, want: 0xA1B2C3D4, want1: 2, want2: 4, want3: nil},
		{name: "Check magic number, major version and  minor version", args: args{dat: []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04}}, want: 0, want1: 0, want2: 0, want3: errors.New("header is too short")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, got3 := getHeader(tt.args.dat)
			if got != tt.want {
				t.Errorf("getHeader() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getHeader() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("getHeader() got2 = %v, want %v", got2, tt.want2)
			}
			if got3 != nil && got3.Error() != tt.want3.Error() {
				t.Errorf("getHeader() got3 = %v, want %v", got3, tt.want3)
			}
		})
	}
}

func Test_parsePacketHeaders(t *testing.T) {
	dat, _ := os.ReadFile("synflood.pcap")
	type args struct {
		dat []byte
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		// TODO: Add test cases.
		{"Check header count", args{dat: dat}, 95829},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parsePacketHeaders(tt.args.dat); got != tt.want {
				t.Errorf("parsePacketHeaders() = %v, want %v", got, tt.want)
			}
		})
	}
}
