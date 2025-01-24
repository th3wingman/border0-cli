package pckparse

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	ipVersion4            = byte(0x04)
	ipv4AddressBytes      = 4
	minIPv4HeaderLen      = 20
	ipv4HeaderSrcIPOffset = 12
	ipv4HeaderDstIPOffset = 16

	ipVersion6            = byte(0x06)
	ipv6AddressBytes      = 16
	ipv6HeaderLen         = 40
	ipv6HeaderSrcIPOffset = 8
	ipv6HeaderDstIPOffset = 24

	icmpHeaderLen                  = 8
	icmpMessageTypeEchoRequestIPv4 = 8
	icmpMessageTypeEchoRequestIPv6 = 128
	icmpMessageTypeEchoReplyIPv4   = 0
	icmpMessageTypeEchoReplyIPv6   = 129
)

const (
	// ProtocolICMP represents the protocol byte in a datagram set to 1 (ICMP).
	ProtocolICMP = uint8(1)

	// ProtocolICMPv6 represents the protocol byte in a datagram set to 58 (ICMPv6).
	ProtocolICMPv6 = uint8(58)

	// ProtocolUDP represents the protocol byte in a datagram set to 17 (UDP).
	ProtocolUDP = uint8(17)

	// ProtocolTCP represents the protocol byte in a datagram set to 6 (TCP).
	ProtocolTCP = uint8(6)
)

// ExtractVersion extracts the IP protocol version from an IP packet.
func ExtractVersion(packet []byte) byte {
	return packet[0] >> 4
}

// ExtractIPs extracts the src and dst IP addresses from an IP packet.
func ExtractIPs(packet []byte) (netip.Addr, netip.Addr, error) {
	ipVersion := packet[0] >> 4
	if ipVersion == ipVersion4 {
		if len(packet) < minIPv4HeaderLen {
			return netip.Addr{}, netip.Addr{}, errors.New("too short to be an IPv4 packet")
		}
		src := netip.AddrFrom4([4]byte(packet[12:16]))
		dst := netip.AddrFrom4([4]byte(packet[16:20]))
		return src, dst, nil
	}
	if ipVersion == ipVersion6 {
		if len(packet) < ipv6HeaderLen {
			return netip.Addr{}, netip.Addr{}, errors.New("too short to be an IPv6 packet")
		}
		src := netip.AddrFrom16([16]byte(packet[8:24]))
		dst := netip.AddrFrom16([16]byte(packet[24:40]))
		return src, dst, nil
	}
	return netip.Addr{}, netip.Addr{}, fmt.Errorf("cannot extract IPs from an IP packet with invalid version bits (must be 4 or 6, but got %d)", ipVersion)
}

// ExtractProtocol extracts the protocol from an IP packet.
func ExtractProtocol(packet []byte) (uint8, error) {
	ipVersion := packet[0] >> 4
	if ipVersion == ipVersion4 {
		if len(packet) < minIPv4HeaderLen {
			return 0, errors.New("too short to be an IPv4 packet")
		}
		// Protocol field is always at byte 9 in IPv4
		return packet[9], nil
	}
	if ipVersion == ipVersion6 {
		if len(packet) < ipv6HeaderLen {
			return 0, errors.New("IPv6 packet too short for protocol extraction")
		}
		// Protocol field is always at byte 6 in IPv6
		return packet[6], nil
	}
	return 0, fmt.Errorf("cannot extract protocol from an IP packet with invalid version bits (must be 4 or 6, but got %d)", ipVersion)
}

// ExtractPorts extracts the src and dst ports from an IP packet.
func ExtractPorts(packet []byte) (uint16, uint16, error) {
	ipVersion := packet[0] >> 4
	if ipVersion == ipVersion4 {
		if len(packet) < minIPv4HeaderLen {
			return 0, 0, errors.New("too short to be an IPv4 packet")
		}
		internetHeaderLength := int(packet[0] & 0x0F) // IPv4 has variable header length
		headerStart := internetHeaderLength * 4
		if len(packet) < headerStart+4 {
			return 0, 0, errors.New("IPv4 packet too short for port extraction")
		}
		src := binary.BigEndian.Uint16(packet[headerStart : headerStart+2])
		dst := binary.BigEndian.Uint16(packet[headerStart+2 : headerStart+4])
		return src, dst, nil
	}
	if ipVersion == ipVersion6 {
		if len(packet) < ipv6HeaderLen {
			return 0, 0, errors.New("IPv6 packet too short for port extraction")
		}
		src := binary.BigEndian.Uint16(packet[40:42])
		dst := binary.BigEndian.Uint16(packet[42:44])
		return src, dst, nil
	}
	return 0, 0, fmt.Errorf("cannot extract ports from an IP packet with invalid version bits (must be 4 or 6, but got %d)", ipVersion)
}

// IsICMPEchoRequest returns true if a packet contains an ICMP
// Echo Request encapsulated in either an IPv4 or IPv6 packet.
func IsICMPEchoRequest(packet []byte) bool {
	ipVersion := packet[0] >> 4
	if ipVersion == ipVersion4 {
		internetHeaderLength := int(packet[0]&0x0F) * 4 // IPv4 has variable header length
		if len(packet) < internetHeaderLength+icmpHeaderLen {
			return false
		}
		icmpType := packet[internetHeaderLength]
		return icmpType == icmpMessageTypeEchoRequestIPv4
	}
	if ipVersion == ipVersion6 {
		if len(packet) < ipv6HeaderLen {
			return false
		}
		nextHeader := packet[6]
		if nextHeader != ProtocolICMPv6 {
			return false
		}
		icmpType := packet[ipv6HeaderLen]
		return icmpType == icmpMessageTypeEchoRequestIPv6
	}
	return false
}

// CraftICMPEchoReplyInPlace crafts an ICMP Echo Reply in-place.
//
// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
func CraftICMPEchoReplyInPlace(packet []byte) error {
	ipVersion := packet[0] >> 4
	if ipVersion == ipVersion4 {
		internetHeaderLength := int(packet[0]&0x0F) * 4 // IPv4 has variable header length
		if len(packet) < internetHeaderLength+icmpHeaderLen {
			return fmt.Errorf("packet too short to contain a complete ICMP message")
		}
		// swap the src and dst addresses in IP header
		srcIP := make([]byte, ipv4AddressBytes)
		dstIP := make([]byte, ipv4AddressBytes)
		copy(srcIP, packet[ipv4HeaderSrcIPOffset:ipv4HeaderSrcIPOffset+ipv4AddressBytes])
		copy(dstIP, packet[ipv4HeaderDstIPOffset:ipv4HeaderDstIPOffset+ipv4AddressBytes])
		copy(packet[ipv4HeaderSrcIPOffset:ipv4HeaderSrcIPOffset+ipv4AddressBytes], dstIP)
		copy(packet[ipv4HeaderDstIPOffset:ipv4HeaderDstIPOffset+ipv4AddressBytes], srcIP)
		// set icmp message type to echo reply
		packet[internetHeaderLength] = icmpMessageTypeEchoReplyIPv4
		// set icmp code to zero for OK reply
		packet[internetHeaderLength+1] = 0
		// adjust checksum
		binary.BigEndian.PutUint16(packet[internetHeaderLength+2:], 0)
		binary.BigEndian.PutUint16(packet[internetHeaderLength+2:], checksum(packet[internetHeaderLength:]))
		return nil
	}
	if ipVersion == ipVersion6 {
		if len(packet) < ipv6HeaderLen+icmpHeaderLen {
			return fmt.Errorf("packet too short to contain a complete ICMPv6 message")
		}
		// swap the src and dst addresses in IP header
		originalSrcIP := make([]byte, ipv6AddressBytes)
		originalDstIP := make([]byte, ipv6AddressBytes)
		copy(originalSrcIP, packet[ipv6HeaderSrcIPOffset:ipv6HeaderSrcIPOffset+ipv6AddressBytes])
		copy(originalDstIP, packet[ipv6HeaderDstIPOffset:ipv6HeaderDstIPOffset+ipv6AddressBytes])
		copy(packet[ipv6HeaderSrcIPOffset:ipv6HeaderSrcIPOffset+ipv6AddressBytes], originalDstIP)
		copy(packet[ipv6HeaderDstIPOffset:ipv6HeaderDstIPOffset+ipv6AddressBytes], originalSrcIP)
		// set icmp (v6) message type to echo reply
		packet[ipv6HeaderLen] = icmpMessageTypeEchoReplyIPv6
		// set icmp (v6) code to zero for OK reply
		packet[ipv6HeaderLen+1] = 0
		// build pseudoheader for checksum
		icmpDataLen := len(packet[ipv6HeaderLen:])
		pseudoHeader := []byte{}
		pseudoHeader = append(pseudoHeader, originalDstIP...) // source ip
		pseudoHeader = append(pseudoHeader, originalSrcIP...) // destination ip
		pseudoHeader = append(pseudoHeader, 0, 0, byte(icmpDataLen>>8), byte(icmpDataLen&0xff))
		pseudoHeader = append(pseudoHeader, 0, 0, 0, 58) // next header (58 for ICMPv6)
		// adjust checksum
		binary.BigEndian.PutUint16(packet[ipv6HeaderLen+2:], 0)
		binary.BigEndian.PutUint16(packet[ipv6HeaderLen+2:], checksum(append(pseudoHeader, packet[ipv6HeaderLen:]...)))
		return nil
	}
	return fmt.Errorf("unknown IP version: %d", ipVersion)
}

// checksum calculates a checksum e.g. for IP / ICMP
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	// pad the last byte if the length is odd
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	// end-around carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	// one's complement as the checksum
	return uint16(^sum)
}
