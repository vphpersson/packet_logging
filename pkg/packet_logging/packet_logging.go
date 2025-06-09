package packet_logging

import (
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	"net"
	"strconv"
)

const unknownPlaceholder = "(unknown)"


func MakeConnectionMessage(base *ecs.Base, suffix string) string {
	if base == nil {
		return ""
	}

	var sourceIpAddress string
	var destinationIpAddress string
	var sourcePort int
	var destinationPort int

	if ecsSource := base.Source; ecsSource != nil {
		sourceIpAddress = ecsSource.Ip
		sourcePort = ecsSource.Port
	}

	if ecsDestination := base.Destination; ecsDestination != nil {
		destinationIpAddress = ecsDestination.Ip
		destinationPort = ecsDestination.Port
	}

	sourcePart := unknownPlaceholder
	if sourceIpAddress != "" && sourcePort != 0 {
		sourcePart = net.JoinHostPort(sourceIpAddress, strconv.Itoa(sourcePort))
	} else if sourceIpAddress != "" {
		sourcePart = sourceIpAddress
	} else if sourcePort != 0 {
		sourcePart = fmt.Sprintf(":%d", sourcePort)
	}

	destinationPart := unknownPlaceholder
	if destinationIpAddress != "" && destinationPort != 0 {
		destinationPart = net.JoinHostPort(destinationIpAddress, strconv.Itoa(destinationPort))
	} else if destinationIpAddress != "" {
		destinationPart = destinationIpAddress
	} else if destinationPort != 0 {
		destinationPart = fmt.Sprintf(":%d", destinationPort)
	}

	transportPart := unknownPlaceholder
	if ecsNetwork := base.Network; ecsNetwork != nil {
		if ecsNetwork.Transport != "" {
			transportPart = ecsNetwork.Transport
		} else if ecsNetwork.IanaNumber != "" {
			transportPart = fmt.Sprintf("(%s)", ecsNetwork.IanaNumber)
		}
	}

	var message string

	if sourcePart == unknownPlaceholder && destinationPart == unknownPlaceholder && transportPart == unknownPlaceholder {
		message = unknownPlaceholder
		if suffix != "" {
			message = suffix
		}
	} else {
		message = fmt.Sprintf("%s to %s %s", sourcePart, destinationPart, transportPart)
		if suffix != "" {
			message += fmt.Sprintf(" - %s", suffix)
		}
	}

	return message
}
