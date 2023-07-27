package main

import (
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
		{name: "Magic number", args: args{dat: []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04}, bytes: 0}, want: []byte{0xD4, 0xC3, 0xB2, 0xA1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getUint32(tt.args.dat, tt.args.bytes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getUint32() = %v, want %v", got, tt.want)
			}
		})
	}
}