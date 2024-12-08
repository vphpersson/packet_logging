package packet_logging

import (
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	"github.com/florianl/go-nflog/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"net"
	"os/user"
	types "packet_logging/pkg/types"
	"strconv"
	"strings"
)

const (
	ActionAccept  = "accept"
	ActionDrop    = "drop"
	ActionReject  = "reject"
	ActionUnknown = "unknown"
)

var netfilterHookIdToName = map[int]string{
	0: "prerouting",
	1: "input",
	2: "forward",
	3: "output",
	4: "postrouting",
}

func parsePayload(payload []byte) *types.LayerCollection {
	if len(payload) == 0 {
		return nil
	}

	for _, ipVersion := range []int{4, 6} {
		layerCollection := types.LayerCollection{IpVersion: ipVersion}

		ok := func() bool {
			if ipVersion == 4 {
				err := gopacket.NewDecodingLayerParser(
					layers.LayerTypeIPv4,
					&layerCollection.Ip4,
					&layerCollection.Tcp,
					&layerCollection.Udp,
				).DecodeLayers(payload, &layerCollection.DecodedLayerTypes)
				if err == nil {
					return true
				}
			} else {
				err := gopacket.NewDecodingLayerParser(
					layers.LayerTypeIPv6,
					&layerCollection.Ip6,
					&layerCollection.Tcp,
					&layerCollection.Udp,
				).DecodeLayers(payload, &layerCollection.DecodedLayerTypes)
				if err == nil {
					return true
				}
			}

			return false
		}()

		if ok {
			return &layerCollection
		}
	}

	return nil
}

func EnrichWithNflogAttribute(nflogAttribute *nflog.Attribute, base *ecs.Base) {
	if nflogAttribute == nil {
		return
	}

	if base == nil {
		return
	}

	timestamp := nflogAttribute.Timestamp
	if timestamp != nil {
		base.Timestamp = timestamp.UTC().Format("2006-01-02T15:04:05.999999Z")
	}

	payload := nflogAttribute.Payload
	if payload != nil && len(*payload) != 0 {
		layerCollection := parsePayload(*payload)
		if layerCollection != nil {
			decodedLayerTypes := layerCollection.DecodedLayerTypes
			for _, layerType := range decodedLayerTypes {
				switch layerType {
				case layers.LayerTypeIPv4:
					EnrichFromIpv4Layer(&layerCollection.Ip4, base)
				case layers.LayerTypeIPv6:
					EnrichFromIpv6Layer(&layerCollection.Ip6, base)
				case layers.LayerTypeTCP:
					EnrichFromTcpLayer(&layerCollection.Tcp, base)
				case layers.LayerTypeUDP:
					EnrichFromUdpLayer(&layerCollection.Udp, base)
				}
			}
		}
	}

	ecsObserver := base.Observer
	if ecsObserver == nil {
		ecsObserver = &ecs.Observer{}
	}

	hook := nflogAttribute.Hook
	var hookName string
	if hook != nil {
		var ok bool
		if hookName, ok = netfilterHookIdToName[int(*hook)]; ok {
			ecsObserver.Hook = hookName
		}
	}

	ecsObserverIngress := ecsObserver.Ingress
	ecsObserverEgress := ecsObserver.Egress

	var ingressInterfaceName string
	if inDev := nflogAttribute.InDev; inDev != nil {
		if ecsObserverIngress == nil {
			ecsObserverIngress = &ecs.ObserverIngressEgress{}
			ecsObserver.Ingress = ecsObserverIngress
		}

		inDevInt := int(*inDev)

		networkInterface, _ := net.InterfaceByIndex(inDevInt)
		if networkInterface != nil {
			ingressInterfaceName = networkInterface.Name
		}

		ecsObserverIngress.Interface = &ecs.Interface{Id: strconv.Itoa(int(*inDev)), Name: ingressInterfaceName}
	}

	var egressInterfaceName string
	if outDev := nflogAttribute.OutDev; outDev != nil {
		if ecsObserverIngress == nil {
			ecsObserverEgress = &ecs.ObserverIngressEgress{}
			ecsObserver.Egress = ecsObserverEgress
		}

		outDevInt := int(*outDev)

		networkInterface, _ := net.InterfaceByIndex(outDevInt)
		if networkInterface != nil {
			egressInterfaceName = networkInterface.Name
		}

		ecsObserverEgress.Interface = &ecs.Interface{Id: strconv.Itoa(int(*outDev)), Name: egressInterfaceName}
	}

	if ecsObserverIngress != nil || ecsObserverEgress != nil {
		base.Observer = ecsObserver
	}

	prefix := nflogAttribute.Prefix
	if prefix != nil {
		prefixString := *prefix

		var actionCode string
		var ruleName string
		var ruleRuleset string

		prefixStringSplit := strings.Split(prefixString, "-")

		switch len(prefixStringSplit) {
		case 2:
			switch hookName {
			case "input":
				if ingressInterfaceName != "" {
					ruleRuleset = fmt.Sprintf(
						"%s_%s",
						strings.ToUpper(hookName),
						strings.ToUpper(ingressInterfaceName),
					)
				}
			case "output":
				if egressInterfaceName != "" {
					ruleRuleset = fmt.Sprintf(
						"%s_%s",
						strings.ToUpper(hookName),
						strings.ToUpper(egressInterfaceName),
					)
				}
			case "prerouting", "forward", "postrouting":
				ruleRuleset = strings.ToUpper(hookName)
			}

			ruleName = prefixStringSplit[0]
			actionCode = prefixStringSplit[1]
		case 3:
			ruleRuleset = prefixStringSplit[0]
			ruleName = prefixStringSplit[1]
			actionCode = prefixStringSplit[2]
		}

		if ruleName != "" || ruleRuleset != "" {
			ecsRule := base.Rule
			if ecsRule == nil {
				ecsRule = &ecs.Rule{}
				base.Rule = ecsRule
			}

			ecsRule.Ruleset = ruleRuleset
			ecsRule.Name = ruleName
		}

		eventAction, eventType := "", ""
		switch actionCode {
		case "A":
			eventAction = ActionAccept
			eventType = "allowed"
		case "D":
			eventAction = ActionDrop
			eventType = "denied"
		case "R":
			eventAction = ActionReject
			eventType = "denied"
		case "U":
			eventAction = ActionUnknown
			eventType = ""
		}

		if eventAction != "" || eventType != "" {
			ecsEvent := base.Event
			if ecsEvent == nil {
				ecsEvent = &ecs.Event{}
				base.Event = ecsEvent
			}

			eventTypeSlice := []string{"connection"}
			if eventType != "" {
				eventTypeSlice = append(eventTypeSlice, eventType)
			}

			ecsEvent.Action = eventAction
			ecsEvent.Type = eventTypeSlice
		}
	}

	userId := nflogAttribute.UID
	if userId != nil {
		ecsUser := base.User
		if ecsUser == nil {
			ecsUser = &ecs.User{}
			base.User = ecsUser
		}

		userIdString := strconv.Itoa(int(*userId))
		ecsUser.Id = userIdString

		lookupUser, _ := user.LookupId(userIdString)
		if lookupUser != nil {
			ecsUser.Name = lookupUser.Username
		}
	}

	groupId := nflogAttribute.GID
	if groupId != nil {
		ecsGroup := base.Group
		if ecsGroup == nil {
			ecsGroup = &ecs.Group{}
			base.Group = ecsGroup
		}

		groupIdString := strconv.Itoa(int(*groupId))
		ecsGroup.Id = groupIdString

		lookupGroup, _ := user.LookupGroupId(groupIdString)
		if lookupGroup != nil {
			ecsGroup.Name = lookupGroup.Name
		}
	}
}
