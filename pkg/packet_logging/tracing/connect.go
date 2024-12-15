package tracing

import (
	"github.com/Motmedel/ecs_go/ecs"
	"packet_logging/pkg/packet_logging"
)

func EnrichWithConnectEvent(base *ecs.Base, event *packet_logging.BpfConnectEvent) {
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
		event.TransportProtocol,
	)

	EnrichWithSourceUser(base, event.UserId)

	EnrichWithProcessInformation(
		base,
		event.ProcessId,
		event.ProcessTitle,
		event.ParentProcessId,
		event.UserId,
		event.GroupId,
	)

	base.Message = packet_logging.MakeConnectionMessage("connect", "", base)
}
