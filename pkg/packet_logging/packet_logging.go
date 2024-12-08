package packet_logging

import (
	"github.com/Motmedel/ecs_go/ecs"
	"github.com/gopacket/gopacket/layers"
	"strconv"
)

var IanaProtocolNumberToText = map[string]string{
	"1":   "icmp",
	"2":   "igmp",
	"6":   "tcp",
	"17":  "udp",
	"47":  "gre",
	"50":  "esp",
	"51":  "ah",
	"88":  "eigrp",
	"89":  "ospf",
	"115": "l2tp",
}

func ExtractTcpFlagsFromLayer(tcpLayer *layers.TCP) []string {
	if tcpLayer == nil {
		return nil
	}

	var flags []string

	if tcpLayer.FIN {
		flags = append(flags, "FIN")
	}
	if tcpLayer.SYN {
		flags = append(flags, "SYN")
	}
	if tcpLayer.RST {
		flags = append(flags, "RST")
	}
	if tcpLayer.PSH {
		flags = append(flags, "PSH")
	}
	if tcpLayer.ACK {
		flags = append(flags, "ACK")
	}
	if tcpLayer.URG {
		flags = append(flags, "URG")
	}
	if tcpLayer.ECE {
		flags = append(flags, "ECE")
	}
	if tcpLayer.CWR {
		flags = append(flags, "CWR")
	}
	if tcpLayer.NS {
		flags = append(flags, "NS")
	}

	return flags
}

func EnrichFromIpv4Layer(ipv4Layer *layers.IPv4, base *ecs.Base) {
	if ipv4Layer == nil {
		return
	}

	if base == nil {
		return
	}

	ecsSource := base.Source
	if ecsSource == nil {
		ecsSource = &ecs.Target{}
		base.Source = ecsSource
	}
	ecsSource.Ip = ipv4Layer.SrcIP.String()

	ecsDestination := base.Destination
	if ecsDestination == nil {
		ecsDestination = &ecs.Target{}
		base.Destination = ecsDestination
	}
	ecsDestination.Ip = ipv4Layer.DstIP.String()

	ecsNetwork := base.Network
	if ecsNetwork == nil {
		ecsNetwork = &ecs.Network{}
		base.Network = ecsNetwork
	}

	protocolNumber := strconv.Itoa(int(ipv4Layer.Protocol))
	ecsNetwork.IanaNumber = protocolNumber
	ecsNetwork.Transport = IanaProtocolNumberToText[protocolNumber]
	ecsNetwork.Type = "ipv4"
}

func EnrichFromIpv6Layer(ipv6Layer *layers.IPv6, base *ecs.Base) {
	if ipv6Layer == nil {
		return
	}

	if base == nil {
		return
	}

	ecsSource := base.Source
	if ecsSource == nil {
		ecsSource = &ecs.Target{}
		base.Source = ecsSource
	}
	ecsSource.Ip = ipv6Layer.SrcIP.String()

	ecsDestination := base.Destination
	if ecsDestination == nil {
		ecsDestination = &ecs.Target{}
		base.Destination = ecsDestination
	}
	ecsDestination.Ip = ipv6Layer.DstIP.String()

	ecsNetwork := base.Network
	if ecsNetwork == nil {
		ecsNetwork = &ecs.Network{}
		base.Network = ecsNetwork
	}

	protocolNumber := strconv.Itoa(int(ipv6Layer.NextHeader))
	ecsNetwork.IanaNumber = protocolNumber
	ecsNetwork.Transport = IanaProtocolNumberToText[protocolNumber]
	ecsNetwork.Type = "ipv6"
}

func EnrichFromTcpLayer(tcpLayer *layers.TCP, base *ecs.Base) {
	if tcpLayer == nil {
		return
	}

	if base == nil {
		return
	}

	ecsSource := base.Source
	if ecsSource == nil {
		ecsSource = &ecs.Target{}
		base.Source = ecsSource
	}
	ecsSource.Port = int(tcpLayer.SrcPort)

	ecsDestination := base.Destination
	if ecsDestination == nil {
		ecsDestination = &ecs.Target{}
		base.Destination = ecsDestination
	}
	ecsDestination.Port = int(tcpLayer.DstPort)

	ecsNetwork := base.Network
	if ecsNetwork == nil {
		ecsNetwork = &ecs.Network{}
		base.Network = ecsNetwork
	}

	ecsNetwork.IanaNumber = "6"
	ecsNetwork.Transport = "tcp"

	ecsTcp := base.Tcp
	if ecsTcp == nil {
		ecsTcp = &ecs.Tcp{}
		base.Tcp = ecsTcp
	}

	ecsTcp.Flags = ExtractTcpFlagsFromLayer(tcpLayer)
	sequenceNumber := int(tcpLayer.Seq)
	ecsTcp.SequenceNumber = &sequenceNumber
	acknowledgementNumber := int(tcpLayer.Ack)
	ecsTcp.AcknowledgementNumber = &acknowledgementNumber
}

func EnrichFromUdpLayer(udpLayer *layers.UDP, base *ecs.Base) {
	if udpLayer == nil {
		return
	}

	if base == nil {
		return
	}

	ecsSource := base.Source
	if ecsSource == nil {
		ecsSource = &ecs.Target{}
		base.Source = ecsSource
	}
	ecsSource.Port = int(udpLayer.SrcPort)

	ecsDestination := base.Destination
	if ecsDestination == nil {
		ecsDestination = &ecs.Target{}
		base.Destination = ecsDestination
	}
	ecsDestination.Port = int(udpLayer.DstPort)

	ecsNetwork := base.Network
	if ecsNetwork == nil {
		ecsNetwork = &ecs.Network{}
		base.Network = ecsNetwork
	}

	ecsNetwork.IanaNumber = "17"
	ecsNetwork.Transport = "udp"
}
