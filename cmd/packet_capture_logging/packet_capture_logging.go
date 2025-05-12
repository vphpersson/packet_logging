package main

import (
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"log/slog"
	"os"
)

const dataset = "packet_capture_logging"

func main() {
	logger := &motmedelErrorLogger.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Next: slog.NewJSONHandler(
					os.Stdout,
					&slog.HandlerOptions{
						AddSource:   false,
						Level:       slog.LevelInfo,
						ReplaceAttr: ecs.TimestampReplaceAttr,
					},
				),
				Extractors: []motmedelLog.ContextExtractor{
					&motmedelLog.ErrorContextExtractor{},
				},
			},
		).With(slog.Group("event", slog.String("dataset", dataset))),
	}
	slog.SetDefault(logger.Logger)

	interfaceName := "lo"
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when obtaining a PCAP handle.",
			motmedelErrors.NewWithTrace(fmt.Errorf("pcap open live: %w", err), interfaceName),
		)
	}

	filter := "port 8080"
	if err := handle.SetBPFFilter(filter); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when setting a BPF filter.",
			motmedelErrors.NewWithTrace(fmt.Errorf("handle set bpf filter: %w", err), handle, interfaceName),
		)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		for _, layer := range packet.Layers() {
			fmt.Println("PACKET LAYER:", layer.LayerType())
		}
	}

	//// Decode a packet
	//packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
	//// Get the TCP layer from this packet
	//if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	//	fmt.Println("This is a TCP packet!")
	//	// Get actual TCP data from this layer
	//	tcp, _ := tcpLayer.(*layers.TCP)
	//	fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
	//}
	//// Iterate over all layers, printing out each layer type
	//for _, layer := range packet.Layers() {
	//	fmt.Println("PACKET LAYER:", layer.LayerType())
	//}
}
