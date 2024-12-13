package packet_logging

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelNet "github.com/Motmedel/utils_go/pkg/net"
	motmedelStrings "github.com/Motmedel/utils_go/pkg/strings"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"log/slog"
	packetLoggingErrors "packet_logging/pkg/errors"
	"path/filepath"
	"strconv"
	"syscall"
)

func EnrichWithExecveEvent(base *ecs.Base, event *BpfExecveEvent) {
	if base == nil {
		return
	}

	if event == nil {
		return
	}

	executable := string(bytes.TrimRight(event.Filename[:], "\x00"))

	var argvStrings []string
	for _, arg := range event.Argv {
		argString := string(bytes.TrimRight(arg[:], "\x00"))
		if argString != "" {
			argvStrings = append(argvStrings, argString)
		}
	}
	argvStrings[0] = executable

	ecsProcess := base.Process
	if ecsProcess == nil {
		ecsProcess = &ecs.Process{}
		base.Process = ecsProcess
	}

	ecsProcess.Args = argvStrings
	ecsProcess.ArgsCount = len(argvStrings)
	ecsProcess.CommandLine = motmedelStrings.ShellJoin(argvStrings)
	ecsProcess.Executable = executable
	ecsProcess.Group = &ecs.Group{Id: strconv.Itoa(int(event.Gid))}
	ecsProcess.Name = filepath.Base(executable)
	ecsProcess.Pid = int(event.Pid)
	ecsProcess.Threat = nil
	ecsProcess.Uptime = 0
	ecsProcess.WorkingDirectory = ""

	ecsProcessUser := ecsProcess.User
	if ecsProcessUser == nil {
		ecsProcessUser = &ecs.User{}
		ecsProcess.User = ecsProcessUser
	}

	ecsProcessUser.Id = strconv.Itoa(int(event.Uid))

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &ecs.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

	ecsProcessParent.Pid = int(event.Ppid)
	ecsProcessParent.Title = string(bytes.TrimRight(event.Comm[:], "\x00"))
}

func EnrichWithConnectEvent(base *ecs.Base, event *BpfConnectEvent) {
	if base == nil {
		return
	}

	if event == nil {
		return
	}

	ecsSource := base.Source
	if ecsSource == nil {
		ecsSource = &ecs.Target{}
		base.Source = ecsSource
	}
	ecsSource.Port = int(event.Sport)

	ecsSourceUser := ecsSource.User
	if ecsSourceUser == nil {
		ecsSourceUser = &ecs.User{}
		ecsSource.User = ecsSourceUser
	}
	ecsSourceUser.Id = strconv.Itoa(int(event.Uid))

	ecsDestination := base.Destination
	if ecsDestination == nil {
		ecsDestination = &ecs.Target{}
		base.Destination = ecsDestination
	}
	ecsDestination.Port = int(event.Dport)

	if event.Af == syscall.AF_INET {
		ecsSource.Ip = motmedelNet.IntToIpv4(event.SaddrV4).String()
		ecsDestination.Ip = motmedelNet.IntToIpv4(event.DaddrV4).String()
	} else if event.Af == syscall.AF_INET6 {
		// TODO: Implement
	}

	ecsProcess := base.Process
	if ecsProcess == nil {
		ecsProcess = &ecs.Process{}
		base.Process = ecsProcess
	}

	ecsProcess.Pid = int(event.Pid)

	ecsProcessUser := ecsProcess.User
	if ecsProcessUser == nil {
		ecsProcessUser = &ecs.User{}
		ecsProcess.User = ecsProcessUser
	}

	ecsProcessUser.Id = strconv.Itoa(int(event.Uid))

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &ecs.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

	ecsProcessParent.Pid = int(event.Ppid)
}

func RunMapReceiver[T any](ctx context.Context, ebpfMap *ebpf.Map, callback func(*T)) error {
	if ebpfMap == nil {
		return packetLoggingErrors.ErrNilEbpfMap
	}

	ringbufReader, err := ringbuf.NewReader(ebpfMap)
	if err != nil {
		return &motmedelErrors.InputError{
			Message: "An error occurred when making a ringbuf reader.",
			Cause:   err,
			Input:   ebpfMap,
		}
	}
	defer ringbufReader.Close()

	go func() {
		<-ctx.Done()
		ringbufReader.Close()
	}()

	for {
		record, err := ringbufReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return &motmedelErrors.CauseError{
				Message: "An error occurred when reading from the ring buffer.",
				Cause:   err,
			}
		}

		if callback != nil {
			go func() {
				var event T
				err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event)
				if err != nil {
					msg := "An error occurred when parsing a record."
					motmedelLog.LogError(
						fmt.Sprintf("%s Skipping.", msg),
						&motmedelErrors.InputError{
							Message: msg,
							Cause:   err,
							Input:   event,
						},
						slog.Default(),
					)
					return
				}

				callback(&event)
			}()
		}
	}
}

func RunTracingMapReceiver[T any](ctx context.Context, program *ebpf.Program, ebpfMap *ebpf.Map, callback func(*T)) error {
	if program == nil {
		return nil
	}

	if ebpfMap == nil {
		return packetLoggingErrors.ErrNilEbpfMap
	}

	tracingLink, err := link.AttachTracing(link.TracingOptions{Program: program})
	if err != nil {
		return &motmedelErrors.InputError{
			Message: "An error occurred when attaching tracing to a program.",
			Cause:   err,
			Input:   program,
		}
	}
	defer tracingLink.Close()

	if err = RunMapReceiver(ctx, ebpfMap, callback); err != nil {
		return &motmedelErrors.InputError{
			Message: "An error occurred when running map receiver.",
			Cause:   err,
			Input:   []any{ebpfMap, callback},
		}
	}

	return nil
}

func RunTracepointMapReceiver[T any](
	ctx context.Context,
	program *ebpf.Program,
	group string,
	name string,
	ebpfMap *ebpf.Map,
	callback func(*T),
) error {
	if program == nil {
		return nil
	}

	if group == "" {
		return packetLoggingErrors.ErrEmptyGroup
	}

	if name == "" {
		return packetLoggingErrors.ErrEmptyName
	}

	if ebpfMap == nil {
		return packetLoggingErrors.ErrNilEbpfMap
	}

	tracepointLink, err := link.Tracepoint(group, name, program, nil)
	if err != nil {
		return &motmedelErrors.InputError{
			Message: "An error occurred when attaching tracepoint to a program.",
			Cause:   err,
			Input:   []any{group, name, program},
		}
	}
	defer tracepointLink.Close()

	if err = RunMapReceiver(ctx, ebpfMap, callback); err != nil {
		return &motmedelErrors.InputError{
			Message: "An error occurred when running map receiver.",
			Cause:   err,
			Input:   []any{ebpfMap, callback},
		}
	}

	return nil
}
