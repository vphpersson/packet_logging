package packet_logging

import (
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelNet "github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"strconv"
	"strings"
)

func ExtractDnsFlagsFromLayer(layer *layers.DNS) []string {
	if layer == nil {
		return nil
	}

	var flags []string

	if layer.AA {
		flags = append(flags, "AA")
	}

	if layer.TC {
		flags = append(flags, "TC")
	}

	if layer.RD {
		flags = append(flags, "RD")
	}

	if layer.RA {
		flags = append(flags, "RA")
	}

	// TODO: No AD and CD??

	return flags
}

func EnrichFromLayer(base *ecs.Base, layer gopacket.Layer, packet gopacket.Packet) {
	if base == nil {
		return
	}

	if layer == nil {
		return
	}

	if packet == nil {
		return
	}

	switch layer.LayerType() {
	case layers.LayerTypeTCP:
		tcpLayer, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			return
		}
		EnrichFromTcpLayer(tcpLayer, base)
	case layers.LayerTypeIPv4:
		ipv4Layer, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			return
		}
		EnrichFromIpv4Layer(ipv4Layer, base)
	case layers.LayerTypeIPv6:
		ipv6Layer, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if !ok {
			return
		}
		EnrichFromIpv6Layer(ipv6Layer, base)
	case layers.LayerTypeUDP:
		udpLayer, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok {
			return
		}
		EnrichFromUdpLayer(udpLayer, base)
	//case layers.LayerTypeTLS:
	//	tlsLayer, ok := packet.Layer(layers.LayerTypeTLS).(*layers.TLS)
	//	if !ok {
	//		return
	//	}
	//
	//	tlsLayer.
	case layers.LayerTypeDNS:
		dnsLayer, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
		if !ok {
			return
		}

		EnrichFromDnsLayer(dnsLayer, base)
	}

}

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

func EnrichFromDnsLayer(layer *layers.DNS, base *ecs.Base) {
	if layer == nil {
		return
	}

	if base == nil {
		return
	}

	ecsNetwork := base.Network
	if ecsNetwork == nil {
		ecsNetwork = &ecs.Network{}
		base.Network = ecsNetwork
	}
	ecsNetwork.Protocol = "dns"

	ecsDns := base.Dns
	if ecsDns == nil {
		ecsDns = &ecs.Dns{}
		base.Dns = ecsDns
	}

	var ecsDnsAnswers []*ecs.DnsAnswer
	var resolvedIps []string
	for _, answer := range layer.Answers {
		data := string(answer.Data)
		answerType := answer.Type.String()

		if answerType == "A" || answerType == "AAAA" {
			resolvedIps = append(resolvedIps, data)
		}

		ecsDnsAnswers = append(
			ecsDnsAnswers,
			&ecs.DnsAnswer{
				Class: answer.Class.String(),
				Data:  data,
				Name:  string(answer.Name),
				Ttl:   int(answer.TTL),
				Type:  answerType,
			},
		)
	}

	var ecsDnsQuestions []*ecs.DnsQuestion
	for _, question := range layer.Questions {
		questionName := string(question.Name)

		ecsDnsQuestion := &ecs.DnsQuestion{
			Class: question.Class.String(),
			Name:  questionName,
			Type:  question.Type.String(),
		}

		if domainBreakdown := motmedelNet.GetDomainBreakdown(questionName); domainBreakdown != nil {
			ecsDnsQuestion.DomainBreakdown = *domainBreakdown
		}

		ecsDnsQuestions = append(ecsDnsQuestions, ecsDnsQuestion)
	}

	var dnsType string
	if layer.QR {
		dnsType = "answer"
		ecsDns.ResponseCode = layer.ResponseCode.String()
	} else {
		dnsType = "question"
	}

	ecsDns.Answers = ecsDnsAnswers
	ecsDns.HeaderFlags = ExtractDnsFlagsFromLayer(layer)
	ecsDns.Id = strconv.Itoa(int(layer.ID))
	ecsDns.OpCode = strings.ToUpper(layer.OpCode.String())
	if len(ecsDnsQuestions) != 0 {
		// TODO: Can there really be more than one?
		ecsDns.Question = ecsDnsQuestions[0]
	}
	ecsDns.ResolvedIp = resolvedIps
	ecsDns.Type = dnsType
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

func MakeConnectionMessage(title string, suffix string, base *ecs.Base) string {
	message := fmt.Sprintf("%s: (incomplete information)", title)
	if suffix != "" {
		message += fmt.Sprintf(" - %s", suffix)
	}

	if base == nil {
		return message
	}

	ecsSource := base.Source
	if ecsSource == nil {
		return message
	}
	sourceIpAddress := ecsSource.Ip
	if sourceIpAddress == "" {
		return message
	}
	sourcePort := ecsSource.Port
	if sourcePort == 0 {
		return message
	}

	ecsDestination := base.Destination
	if ecsDestination == nil {
		return message
	}
	destinationIpAddress := ecsDestination.Ip
	if destinationIpAddress == "" {
		return message
	}
	destinationPort := ecsDestination.Port
	if destinationPort == 0 {
		return message
	}

	ecsNetwork := base.Network
	if ecsNetwork == nil {
		return message
	}
	transport := ecsNetwork.Transport
	if transport == "" {
		return message
	}

	message = fmt.Sprintf(
		"%s: [%s]:%d -> [%s]:%d %s",
		title,
		sourceIpAddress,
		sourcePort,
		destinationIpAddress,
		destinationPort,
		transport,
	)
	if suffix != "" {
		message += fmt.Sprintf(" - %s", suffix)
	}

	return message
}
