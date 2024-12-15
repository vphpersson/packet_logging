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
	ecsProcess.Name = filepath.Base(executable)

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &ecs.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

	ecsProcessParent.Title = ecsProcess.Title

	base.Message = fmt.Sprintf("execve: %s -> %s", ecsProcessParent.Title, ecsProcess.CommandLine)

}
