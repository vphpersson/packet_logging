package main

import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"os"
	"os/signal"
	"packet_logging/pkg/packet_logging"
	"packet_logging/pkg/packet_logging/tracing"
	"sync"
	"syscall"
	"time"
)

type TimedEvecveEntry struct {
	Event *packet_logging.BpfExecveEvent
	Timer *time.Timer
}

func ProcessExists(pid int) (bool, error) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}
	defer process.Release()

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
		).With(slog.Group("event", slog.String("dataset", "tracing"))),
	}
	slog.SetDefault(logger.Logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		cancel()
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when removing the memory lock.",
			fmt.Errorf("rlimit remove mem lock: %w", err),
		)
	}

	objs := packet_logging.BpfObjects{}
	if err := packet_logging.LoadBpfObjects(&objs, nil); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when loading objects.",
			fmt.Errorf("load bpf objects: %w", err),
			objs,
		)
	}
	defer objs.Close()

	timedExecveEntryMap := make(map[uint32]*TimedEvecveEntry)
	var timedExecveEntryMapMutex sync.RWMutex

	var printMutex sync.Mutex

	errGroup, _ := errgroup.WithContext(context.Background())

	errGroup.Go(
		func() error {
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

						data, err := json.Marshal(base)
						if err != nil {
							logger.Error(
								"An error occurred when marshalling a execve base. Skipping.",
								motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), base),
							)
							return
						}

						printMutex.Lock()
						fmt.Println(string(data))
						printMutex.Unlock()
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
				return motmedelErrors.NewWithTrace(fmt.Errorf("run tracepoint map receiver (execve): %w", err))
			}

			return nil
		},
	)

	errGroup.Go(
		func() error {
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
						logger.Error(
							"An error occurred when marshalling a connect base. Skipping.",
							motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), base),
						)
						return
					}

					printMutex.Lock()
					fmt.Println(string(data))
					printMutex.Unlock()
				},
			)
			if err != nil {
				return motmedelErrors.NewWithTrace(fmt.Errorf("run tracing map receiver (tcp connect): %w", err))
			}

			return nil
		},
	)

	errGroup.Go(
		func() error {
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
						logger.Error(
							"An error occurred when marshalling a destroy connection base. Skipping.",
							motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), base),
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
				return motmedelErrors.NewWithTrace(fmt.Errorf("run tracing map receiver (nf ct helper descroy): %w", err))
			}

			return nil
		},
	)

	errGroup.Go(
		func() error {
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
						logger.Error(
							"An error occurred when marshalling a tcp retransmission skb base. Skipping.",
							motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), base),
						)
						return
					}

					printMutex.Lock()
					fmt.Println(string(data))
					printMutex.Unlock()
				},
			)
			if err != nil {
				return motmedelErrors.NewWithTrace(fmt.Errorf("run tracepoint map receiver (tcp retransmit skb): %w", err))
			}

			return nil
		},
	)

	errGroup.Go(
		func() error {
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
						logger.Error(
							"An error occurred when marshalling a tcp retransmit synack skb base.",
							motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), base),
						)
						return
					}

					printMutex.Lock()
					fmt.Println(string(data))
					printMutex.Unlock()
				},
			)
			if err != nil {
				return motmedelErrors.NewWithTrace(fmt.Errorf("run tracepoint map receiver (tcp retransmit skb): %w", err))
			}

			return nil
		},
	)

	if err := errGroup.Wait(); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when initializing a tracer.",
			fmt.Errorf("errgroup wait: %w", err),
		)
	}

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
