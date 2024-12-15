package tracing

import (
	"github.com/Motmedel/ecs_go/ecs"
	"packet_logging/pkg/packet_logging"
)

func EnrichWithTcpRetransmissionEvent(base *ecs.Base, event *packet_logging.BpfTcpRetransmissionEvent) {
	if base == nil {
		return
	}

	if event == nil {
		return
	}

	base.Timestamp = ConvertEbpfTimestampToIso8601(event.TimestampNs, GetBootTime())

	EnrichWithConnectionInformationTransport(
		base,
		event.SourceAddress,
		event.SourcePort,
		event.DestinationAddress,
		event.DestinationPort,
		event.AddressFamily,
		6,
	)

	base.Message = packet_logging.MakeConnectionMessage("TCP retransmission", "", base)
}

func EnrichWithTcpRetransmissionSynAckEvent(base *ecs.Base, event *packet_logging.BpfTcpRetransmissionSynackEvent) {
	if base == nil {
		return
	}

	if event == nil {
		return
	}

	base.Timestamp = ConvertEbpfTimestampToIso8601(event.TimestampNs, GetBootTime())

	EnrichWithConnectionInformationTransport(
		base,
		event.SourceAddress,
		event.SourcePort,
		event.DestinationAddress,
		event.DestinationPort,
		event.AddressFamily,
		6,
	)

	base.Message = packet_logging.MakeConnectionMessage("TCP retransmission", "", base)
}
