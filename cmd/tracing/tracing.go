package main

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

func ProcessExists(pid int) (bool, error) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}

	return process.Signal(syscall.Signal(0)) == nil, nil
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
			&motmedelErrors.InputError{
				Message: msg,
				Cause:   err,
				Input:   objs,
			},
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
		err := packet_logging.RunTracepointMapReceiver(
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

					base := &ecs.Base{}

					packet_logging.EnrichWithExecveEvent(base, event)

					ecsEvent := base.Event
					if ecsEvent == nil {
						ecsEvent = &ecs.Event{}
						base.Event = ecsEvent
					}
					ecsEvent.Reason = "An execve call was made."

					if ecsProcess := base.Process; ecsProcess != nil {
						var parentString string
						if ecsProcessParent := ecsProcess.Parent; ecsProcessParent != nil {
							parentString = fmt.Sprintf("%s -> ", ecsProcessParent.Title)
						}

						base.Message = fmt.Sprintf("execve: %s%s", parentString, ecsProcess.CommandLine)
					}

					d, _ := json.Marshal(base)
					printMutex.Lock()
					fmt.Println(string(d))
					printMutex.Unlock()
				}()

				key := event.Pid

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
					processExists, err := ProcessExists(int(event.Pid))
					if processExists && err != nil {
						timedExecveEntryMapMutex.Lock()
						delete(timedExecveEntryMap, event.Pid)
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
		err := packet_logging.RunTracingMapReceiver(
			ctx,
			program,
			ebpfMap,
			func(event *packet_logging.BpfConnectEvent) {
				if event == nil {
					return
				}

				ecsBase := &ecs.Base{}

				timedExecveEntryMapMutex.RLock()
				execveEvent, ok := timedExecveEntryMap[event.Pid]
				timedExecveEntryMapMutex.RUnlock()
				if ok {
					packet_logging.EnrichWithExecveEvent(ecsBase, execveEvent.Event)
				}

				packet_logging.EnrichWithConnectEvent(ecsBase, event)

				//d, _ := json.Marshal(ecsBase)
				//fmt.Println(string(d))
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

	<-ctx.Done()
}
