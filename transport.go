package dns

import (
	"context"
	"net/netip"
	"net/url"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/miekg/dns"
)

type TransportConstructor = func(options TransportOptions) (Transport, error)

type Transport interface {
	Name() string
	Start() error
	Reset()
	Close() error
	Raw() bool
	Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error)
	Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error)
}

type TransportOptions struct {
	Context      context.Context
	Logger       logger.ContextLogger
	Name         string
	Dialer       N.Dialer
	Address      string
	ClientSubnet netip.Prefix
}

var transports map[string]TransportConstructor

func RegisterTransport(schemes []string, constructor TransportConstructor) {
	if transports == nil {
		transports = make(map[string]TransportConstructor)
	}
	for _, scheme := range schemes {
		transports[scheme] = constructor
	}
}

func CreateTransport(options TransportOptions) (Transport, error) {
	constructor := transports[options.Address]
	if constructor == nil {
		serverURL, _ := url.Parse(options.Address)
		var scheme string
		if serverURL != nil {
			scheme = serverURL.Scheme
		}
		constructor = transports[scheme]
	}
	if constructor == nil {
		return nil, E.New("unknown DNS server format: " + options.Address)
	}
	options.Context = contextWithTransportName(options.Context, options.Name)
	transport, err := constructor(options)
	if err != nil {
		return nil, err
	}
	if options.ClientSubnet.IsValid() {
		transport = &edns0SubnetTransportWrapper{transport, options.ClientSubnet}
	}
	return transport, nil
}
