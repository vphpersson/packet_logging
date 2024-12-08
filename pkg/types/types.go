package types

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type LayerCollection struct {
	IpVersion         int
	DecodedLayerTypes []gopacket.LayerType
	Eth               layers.Ethernet
	Ip4               layers.IPv4
	Ip6               layers.IPv6
	Tcp               layers.TCP
	Udp               layers.UDP
}
