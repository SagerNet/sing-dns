package dns

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
)

type edns0SubnetTransportWrapper struct {
	Transport
	clientSubnet netip.Prefix
}

func (t *edns0SubnetTransportWrapper) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	message = SetClientSubnet(message, t.clientSubnet, false)
	return t.Transport.Exchange(ctx, message)
}

func SetClientSubnet(message *dns.Msg, clientSubnet netip.Prefix, override bool) *dns.Msg {
	return setClientSubnet(message, clientSubnet, override, true)
}

func setClientSubnet(message *dns.Msg, clientSubnet netip.Prefix, override bool, clone bool) *dns.Msg {
	var (
		optRecord    *dns.OPT
		subnetOption *dns.EDNS0_SUBNET
	)
findExists:
	for _, record := range message.Extra {
		var isOPTRecord bool
		if optRecord, isOPTRecord = record.(*dns.OPT); isOPTRecord {
			for _, option := range optRecord.Option {
				var isEDNS0Subnet bool
				subnetOption, isEDNS0Subnet = option.(*dns.EDNS0_SUBNET)
				if isEDNS0Subnet {
					if !override {
						return message
					}
					break findExists
				}
			}
		}
	}
	if optRecord == nil {
		exMessage := *message
		message = &exMessage
		optRecord = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		}
		message.Extra = append(message.Extra, optRecord)
	} else if clone {
		return setClientSubnet(message.Copy(), clientSubnet, override, false)
	}
	if subnetOption == nil {
		subnetOption = new(dns.EDNS0_SUBNET)
		subnetOption.Code = dns.EDNS0SUBNET
		optRecord.Option = append(optRecord.Option, subnetOption)
	}
	if clientSubnet.Addr().Is4() {
		subnetOption.Family = 1
	} else {
		subnetOption.Family = 2
	}
	subnetOption.SourceNetmask = uint8(clientSubnet.Bits())
	subnetOption.Address = clientSubnet.Addr().AsSlice()
	return message
}
