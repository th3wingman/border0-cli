package endpoint

import (
	"encoding/binary"
	"net/netip"
)

const (
	randomUint64ByteOffset = 2
	portBytes              = 2
	dummyPort              = 12345
	ipv4ClassEFirstOctet   = byte(240)
	ipv6Bytes              = 16
	ipv4Bytes              = 4
	portBitShift           = 8
)

func fakeUdp4AddrPortClassE(randUint64 uint64) []byte {
	addrBytes := [ipv6Bytes]byte{ipv4ClassEFirstOctet}
	binary.BigEndian.PutUint64(addrBytes[randomUint64ByteOffset:], randUint64)
	addr := netip.AddrPortFrom(netip.AddrFrom16(addrBytes).Unmap(), dummyPort)
	ip := addr.Addr().Unmap()
	fullIPBytes := ip.As16()
	ipBytes := fullIPBytes[:]
	if ip.Is4() {
		ipBytes = ipBytes[ipv6Bytes-ipv4Bytes:]
	}
	result := make([]byte, 0, len(ipBytes)+portBytes)
	result = append(result, ipBytes...)
	result = append(result, byte(addr.Port()), byte(addr.Port()>>portBitShift))
	return result
}
