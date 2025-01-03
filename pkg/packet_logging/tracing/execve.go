package tracing

import (
	"bytes"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelStrings "github.com/Motmedel/utils_go/pkg/strings"
	"packet_logging/pkg/packet_logging"
	"path/filepath"
)

func EnrichWithExecveEvent(base *ecs.Base, event *packet_logging.BpfExecveEvent) {
	if base == nil {
		return
	}

	if event == nil {
		return
	}

	base.Timestamp = ConvertEbpfTimestampToIso8601(event.TimestampNs, GetBootTime())

	EnrichWithProcessInformation(
		base,
		event.ProcessId,
		event.ProcessTitle,
		event.ParentProcessId,
		event.UserId,
		event.GroupId,
	)

	executable := string(bytes.TrimRight(event.Filename[:], "\x00"))

	argvStrings := []string{executable}
	for i := uint32(1); i < event.Argc && int(i) < len(event.Argv); i++ {
		argString := string(bytes.TrimRight(event.Argv[i][:], "\x00"))
		if argString != "" {
			argvStrings = append(argvStrings, argString)
		}
	}

	ecsProcess := base.Process
	if ecsProcess == nil {
		ecsProcess = &ecs.Process{}
		base.Process = ecsProcess
	}

	ecsProcess.Args = argvStrings
	ecsProcess.ArgsCount = len(argvStrings)
	ecsProcess.CommandLine = motmedelStrings.ShellJoin(argvStrings)
	ecsProcess.Executable = executable
	ecsProcess.Name = filepath.Base(executable)

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &ecs.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

	ecsProcessParent.Title = ecsProcess.Title

	base.Message = fmt.Sprintf("execve: %s -> %s", ecsProcessParent.Title, ecsProcess.CommandLine)

}
