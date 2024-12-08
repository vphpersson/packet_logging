package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"github.com/florianl/go-nflog/v2"
	"github.com/mdlayher/netlink"
	"log/slog"
	"os"
	"packet_logging/pkg/packet_logging"
	"snqk.dev/slog/meld"
	"sync"
	"time"
)

const dataset = "firewall_logging"

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

	groupFlag := flag.Int("group", 0, "The NFLOG group to listen on.")
	flag.Parse()

	if groupFlag == nil || *groupFlag == 0 {
		logger.Error("No group was provided. Exiting.")
		os.Exit(1)
	}

	netfilterLogHandler, err := nflog.Open(&nflog.Config{Group: uint16(*groupFlag), Copymode: nflog.CopyPacket})
	if err != nil {
		msg := "An error occurred when opening a connection to the Netfilter log subsystem."
		motmedelLog.LogFatal(
			fmt.Sprintf("%s Exiting.", msg),
			&motmedelErrors.CauseError{Message: msg, Cause: err},
			logger,
			1,
		)
	}
	defer netfilterLogHandler.Close()

	// Avoid receiving ENOBUFS errors.
	option := netlink.NoENOBUFS
	if err := netfilterLogHandler.SetOption(option, true); err != nil {
		msg := "An error occurred when setting the NoENOBUFS Netlink option."
		motmedelLog.LogFatal(
			fmt.Sprintf("%s Exiting.", msg),
			&motmedelErrors.CauseError{Message: msg, Cause: err},
			logger,
			1,
		)
	}

	ctx := context.Background()
	var printLock sync.Mutex

	err = netfilterLogHandler.RegisterWithErrorFunc(
		ctx,
		func(attrs nflog.Attribute) int {
			timestamp := time.Now()

			document := &ecs.Base{Event: &ecs.Event{Dataset: dataset}}
			packet_logging.EnrichWithNflogAttribute(&attrs, document)

			if document.Timestamp == "" {
				document.Timestamp = timestamp.UTC().Format("2006-01-02T15:04:05.999999999Z")
			}

			documentData, err := json.Marshal(document)
			if err != nil {
				msg := "An error occurred when marshalling a document."
				motmedelLog.LogError(
					fmt.Sprintf("%s Skipping.", msg),
					&motmedelErrors.InputError{
						Message: msg,
						Cause:   err,
						Input:   document,
					},
					logger,
				)
				return 0
			}

			printLock.Lock()
			defer printLock.Unlock()
			fmt.Println(string(documentData))

			return 0
		},
		func(err error) int {
			msg := "An error occurred when receiving from the Netfilter log handler."
			motmedelLog.LogError(msg, &motmedelErrors.CauseError{Message: msg, Cause: err}, logger)
			return 0
		},
	)
	if err != nil {
		msg := "An error occurred when registering Netfilter hook functions."
		motmedelLog.LogFatal(
			fmt.Sprintf("%s Exiting.", msg),
			&motmedelErrors.CauseError{
				Message: msg,
				Cause:   err,
			},
			logger,
			1,
		)
	}

	<-ctx.Done()
}
