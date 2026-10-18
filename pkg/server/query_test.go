package server

import (
	"encoding/binary"
	"testing"

	"github.com/miekg/dns"
)

func TestUnpackQueryRejectsPaddedECSIdentity(t *testing.T) {
	for _, tt := range []struct {
		name   string
		family uint16
		bits   uint8
		length int
		valid  bool
	}{
		{"ipv4_full", 1, 32, 4, true},
		{"ipv4_short", 1, 32, 3, false},
		{"ipv4_long", 1, 32, 5, false},
		{"ipv4_prefix", 1, 24, 3, true},
		{"ipv6_full", 2, 128, 16, true},
		{"ipv6_short", 2, 128, 15, false},
		{"ipv6_long", 2, 128, 17, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			q := new(dns.Msg)
			q.SetQuestion("example.org.", dns.TypeA)
			q.SetEdns0(1232, false)
			data := make([]byte, 4+tt.length)
			binary.BigEndian.PutUint16(data, tt.family)
			data[2] = tt.bits
			data[4] = 192
			q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_LOCAL{Code: dns.EDNS0SUBNET, Data: data}}
			b, err := q.Pack()
			if err != nil {
				t.Fatal(err)
			}
			_, err = unpackQuery(b)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v, unpack error=%v", tt.valid, err)
			}
		})
	}
}
