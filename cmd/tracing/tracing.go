package main

import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"github.com/cilium/ebpf/rlimit"
	"log/slog"
	"os"
	"os/signal"
	"packet_logging/pkg/packet_logging"
	"packet_logging/pkg/packet_logging/tracing"
	"snqk.dev/slog/meld"
	"sync"
	"syscall"
	"time"
)

const dataset = "tracing"

type TimedEvecveEntry struct {
	Event *packet_logging.BpfExecveEvent
	Timer *time.Timer
}

// TODO: Replace with standard-library function.

func ProcessExists(pid int) (bool, error) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}

	return process.Signal(syscall.Signal(0)) == nil, nil
}

var tcpStates = map[int32]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
	13: "BOUND_INACTIVE",
	14: "MAX_STATES",
}

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		cancel()
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		msg := "An error occurred when removing the memory lock."
		motmedelLog.LogFatal(
			fmt.Sprintf("%s Exiting.", msg),
			&motmedelErrors.CauseError{Message: msg, Cause: err},
			logger,
			1,
		)
	}

	objs := packet_logging.BpfObjects{}
	if err := packet_logging.LoadBpfObjects(&objs, nil); err != nil {
		msg := "An error occurred when loading objects."
		motmedelLog.LogFatal(
			fmt.Sprintf("%s Exiting.", msg),
			&motmedelErrors.InputError{Message: msg, Cause: err, Input: objs},
			logger,
			1,
		)
	}
	defer objs.Close()

	timedExecveEntryMap := make(map[uint32]*TimedEvecveEntry)
	var timedExecveEntryMapMutex sync.RWMutex

	var printMutex sync.Mutex

	go func() {
		program := objs.BpfPrograms.EnterExecve
		ebpfMap := objs.BpfMaps.ExecveEvents
		err := tracing.RunTracepointMapReceiver(
			ctx,
			program,
			"syscalls",
			"sys_enter_execve",
			ebpfMap,
			func(event *packet_logging.BpfExecveEvent) {
				if event == nil {
					return
				}

				var waitGroup sync.WaitGroup

				waitGroup.Add(1)
				go func() {
					defer waitGroup.Done()

					base := &ecs.Base{
						Event: &ecs.Event{
							Reason:  "An execve call was made.",
							Dataset: "tracing.execve",
						},
					}
					tracing.EnrichWithExecveEvent(base, event)

					_, err := json.Marshal(base)
					if err != nil {
						msg := "An error occurred when marshalling a destroy connection base."
						motmedelLog.LogError(
							fmt.Sprintf("%s Skipping.", msg),
							&motmedelErrors.InputError{Message: msg, Cause: err, Input: base},
							logger,
						)
						return
					}

					//printMutex.Lock()
					//fmt.Println(string(data))
					//printMutex.Unlock()
				}()

				key := event.ProcessId

				timedExecveEntryMapMutex.Lock()
				te, ok := timedExecveEntryMap[key]
				if !ok {
					te = &TimedEvecveEntry{}
				}

				te.Event = event
				timedExecveEntryMap[key] = te

				timedExecveEntryMapMutex.Unlock()

				if teTimer := te.Timer; teTimer != nil {
					teTimer.Stop()
				}

				var afterFunc func()

				afterFunc = func() {
					processExists, err := ProcessExists(int(event.ProcessId))
					if processExists && err != nil {
						timedExecveEntryMapMutex.Lock()
						delete(timedExecveEntryMap, event.ProcessId)
						timedExecveEntryMapMutex.Unlock()
					} else {
						te.Timer = time.AfterFunc(30*time.Second, afterFunc)
					}
				}

				te.Timer = time.AfterFunc(30*time.Second, afterFunc)

				waitGroup.Wait()
			},
		)
		if err != nil {
			msg := "An error occurred when setting up a receiver."
			motmedelLog.LogFatal(
				fmt.Sprintf("%s Exiting.", msg),
				&motmedelErrors.InputError{Message: msg, Cause: err, Input: []any{program, ebpfMap}},
				logger,
				1,
			)
		}
	}()

	go func() {
		program := objs.BpfPrograms.TcpConnect
		ebpfMap := objs.BpfMaps.ConnectEvents
		err := tracing.RunTracingMapReceiver(
			ctx,
			program,
			ebpfMap,
			func(event *packet_logging.BpfConnectEvent) {
				if event == nil {
					return
				}

				base := &ecs.Base{
					Event: &ecs.Event{
						Reason:  "A connect call was made.",
						Dataset: "tracing.connect",
					},
				}

				timedExecveEntryMapMutex.RLock()
				execveEvent, ok := timedExecveEntryMap[event.ProcessId]
				timedExecveEntryMapMutex.RUnlock()
				if ok {
					tracing.EnrichWithExecveEvent(base, execveEvent.Event)
				}

				tracing.EnrichWithConnectEvent(base, event)

				data, err := json.Marshal(base)
				if err != nil {
					msg := "An error occurred when marshalling a connect base."
					motmedelLog.LogError(
						fmt.Sprintf("%s Skipping.", msg),
						&motmedelErrors.InputError{Message: msg, Cause: err, Input: base},
						logger,
					)
					return
				}

				printMutex.Lock()
				fmt.Println(string(data))
				printMutex.Unlock()
			},
		)
		if err != nil {
			msg := "An error occurred when setting up a receiver."
			motmedelLog.LogFatal(
				fmt.Sprintf("%s Exiting.", msg),
				&motmedelErrors.InputError{Message: msg, Cause: err, Input: []any{program, ebpfMap}},
				logger,
				1,
			)
		}
	}()

	go func() {
		program := objs.BpfPrograms.NfCtHelperDestroy
		ebpfMap := objs.BpfMaps.DestroyConnectionEvents
		err := tracing.RunTracingMapReceiver(
			ctx,
			program,
			ebpfMap,
			func(event *packet_logging.BpfDestroyConnectionEvent) {
				if event == nil {
					return
				}

				base := &ecs.Base{
					Event: &ecs.Event{
						Reason:  "A connection was destroyed by Conntrack.",
						Dataset: "tracing.destroy_connection",
					},
				}

				tracing.EnrichWithDestroyConnectionEvent(base, event)

				data, err := json.Marshal(base)
				if err != nil {
					msg := "An error occurred when marshalling a destroy connection base."
					motmedelLog.LogError(
						fmt.Sprintf("%s Skipping.", msg),
						&motmedelErrors.InputError{
							Message: msg,
							Cause:   err,
							Input:   base,
						},
						logger,
					)
					return
				}

				//s := translateStatusBits(int(event.ConntrackStatus))
				//fmt.Println(strings.Join(s, ", "))

				printMutex.Lock()
				fmt.Println(string(data))
				printMutex.Unlock()
			},
		)
		if err != nil {
			msg := "An error occurred when setting up a receiver."
			motmedelLog.LogFatal(
				fmt.Sprintf("%s Exiting.", msg),
				&motmedelErrors.InputError{Message: msg, Cause: err, Input: []any{program, ebpfMap}},
				logger,
				1,
			)
		}
	}()

	go func() {
		program := objs.BpfPrograms.TcpRetransmitSkb
		ebpfMap := objs.BpfMaps.TcpRetransmissionEvents
		err := tracing.RunTracepointMapReceiver(
			ctx,
			program,
			"tcp",
			"tcp_retransmit_skb",
			ebpfMap,
			func(event *packet_logging.BpfTcpRetransmissionEvent) {
				if event == nil {
					return
				}

				base := &ecs.Base{
					Event: &ecs.Event{
						Reason:  "A TCP retransmission was performed.",
						Dataset: "tracing.tcp_retransmit_skb",
					},
				}

				tracing.EnrichWithTcpRetransmissionEvent(base, event)

				data, err := json.Marshal(base)
				if err != nil {
					msg := "An error occurred when marshalling a tcp retransmission skb base."
					motmedelLog.LogError(
						fmt.Sprintf("%s Skipping.", msg),
						&motmedelErrors.InputError{Message: msg, Cause: err, Input: base},
						logger,
					)
					return
				}

				printMutex.Lock()
				fmt.Println(string(data))
				printMutex.Unlock()
			},
		)
		if err != nil {
			msg := "An error occurred when setting up a receiver."
			motmedelLog.LogFatal(
				fmt.Sprintf("%s Exiting.", msg),
				&motmedelErrors.InputError{Message: msg, Cause: err, Input: []any{program, ebpfMap}},
				logger,
				1,
			)
		}
	}()

	go func() {
		program := objs.BpfPrograms.TcpRetransmitSkb
		ebpfMap := objs.BpfMaps.TcpRetransmissionSynackEvents
		err := tracing.RunTracepointMapReceiver(
			ctx,
			program,
			"tcp",
			"tcp_retransmit_synack",
			ebpfMap,
			func(event *packet_logging.BpfTcpRetransmissionSynackEvent) {
				if event == nil {
					return
				}

				base := &ecs.Base{
					Event: &ecs.Event{
						Reason:  "A TCP retransmission was performed.",
						Dataset: "tracing.tcp_retransmit_synack",
					},
				}

				tracing.EnrichWithTcpRetransmissionSynAckEvent(base, event)

				data, err := json.Marshal(base)
				if err != nil {
					msg := "An error occurred when marshalling a tcp retransmission skb base."
					motmedelLog.LogError(
						fmt.Sprintf("%s Skipping.", msg),
						&motmedelErrors.InputError{Message: msg, Cause: err, Input: base},
						logger,
					)
					return
				}

				printMutex.Lock()
				fmt.Println(string(data))
				printMutex.Unlock()
			},
		)
		if err != nil {
			msg := "An error occurred when setting up a receiver."
			motmedelLog.LogFatal(
				fmt.Sprintf("%s Exiting.", msg),
				&motmedelErrors.InputError{Message: msg, Cause: err, Input: []any{program, ebpfMap}},
				logger,
				1,
			)
		}
	}()

	//go func() {
	//	program := objs.BpfPrograms.SockSetState
	//	ebpfMap := objs.BpfMaps.TcpStateEvents
	//	err := packet_logging.RunTracepointMapReceiver(
	//		ctx,
	//		program,
	//		"sock",
	//		"inet_sock_set_state",
	//		ebpfMap,
	//		func(event *packet_logging.BpfTcpStateEvent) {
	//			if event == nil {
	//				return
	//			}
	//
	//			message := fmt.Sprintf(
	//				"[%s]:%d -> [%s]:%d: %s -> %s",
	//				motmedelNet.IntToIpv4(event.SaddrV4),
	//				event.Sport,
	//				motmedelNet.IntToIpv4(event.DaddrV4),
	//				event.Dport,
	//				tcpStates[event.OldState],
	//				tcpStates[event.NewState],
	//			)
	//
	//			printMutex.Lock()
	//			fmt.Println(message)
	//			printMutex.Unlock()
	//		},
	//	)
	//	if err != nil {
	//		msg := "An error occurred when setting up a receiver."
	//		motmedelLog.LogFatal(
	//			fmt.Sprintf("%s Exiting.", msg),
	//			&motmedelErrors.InputError{Message: msg, Cause: err, Input: []any{program, ebpfMap}},
	//			logger,
	//			1,
	//		)
	//	}
	//}()

	<-ctx.Done()
}
