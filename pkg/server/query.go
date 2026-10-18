package server

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
)

func readQueryFromTCP(r io.Reader) (*dns.Msg, error) {
	b, err := dnsutils.ReadRawMsgFromTCP(r)
	if err != nil {
		return nil, err
	}
	defer pool.ReleaseBuf(b)
	return unpackQuery(*b)
}

func unpackQuery(b []byte) (*dns.Msg, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return nil, err
	}
	// miekg/dns pads short ECS addresses and truncates long ones while
	// unpacking. Validate the wire length before trusting a full address.
	for _, rr := range m.Extra {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			continue
		}
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0SUBNET {
				if err := validateECSWire(b); err != nil {
					return nil, err
				}
				return m, nil
			}
		}
	}
	return m, nil
}

func validateECSWire(b []byte) error {
	if len(b) < 12 {
		return dns.ErrBuf
	}
	read16 := func(off int) int { return int(binary.BigEndian.Uint16(b[off:])) }
	off := 12
	for i := 0; i < read16(4); i++ {
		_, next, err := dns.UnpackDomainName(b, off)
		if err != nil || next+4 > len(b) {
			return dns.ErrBuf
		}
		off = next + 4
	}
	for i, count := 0, read16(6)+read16(8)+read16(10); i < count; i++ {
		_, next, err := dns.UnpackDomainName(b, off)
		if err != nil || next+10 > len(b) {
			return dns.ErrBuf
		}
		typ := read16(next)
		end := next + 10 + read16(next+8)
		if end > len(b) {
			return dns.ErrBuf
		}
		if typ == int(dns.TypeOPT) {
			for p := next + 10; p < end; {
				if p+4 > end {
					return dns.ErrBuf
				}
				code, length := read16(p), read16(p+2)
				p += 4
				if p+length > end {
					return dns.ErrBuf
				}
				if code == dns.EDNS0SUBNET {
					if length < 4 || length != 4+(int(b[p+2])+7)/8 {
						return fmt.Errorf("invalid ECS address length")
					}
				}
				p += length
			}
		}
		off = end
	}
	return nil
}
