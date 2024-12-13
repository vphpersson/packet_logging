package main

import (
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	"github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"log/slog"
	"os"
	"snqk.dev/slog/meld"
)

const dataset = "packet_capture_logging"

func main() {
	logger := slog.New(
		meld.NewHandler(
			slog.NewJSONHandler(
				os.Stderr,
				&slog.HandlerOptions{
					AddSource:   false,
					Level:       slog.LevelInfo,
					ReplaceAttr: ecs.TimestampReplaceAttr,
				},
			),
		),
	)
	logger = logger.With(slog.Group("event", slog.String("dataset", dataset)))
	slog.SetDefault(logger)

	interfaceName := "wlp0s20f3"
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		msg := "An error occurred when obtaining a PCAP handle."
		motmedelLog.LogFatal(
			fmt.Sprintf("%s Exiting.", msg),
			&errors.InputError{
				Message: msg,
				Cause:   err,
				Input:   interfaceName,
			},
			logger,
			1,
		)
	}

	filter := "port 53"
	if err := handle.SetBPFFilter(filter); err != nil {
		msg := "An error occurred when setting a BPF filter."
		motmedelLog.LogFatal(
			fmt.Sprintf("%s Exiting.", msg),
			&errors.InputError{
				Message: msg,
				Cause:   err,
				Input:   filter,
			},
			logger,
			1,
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
