package dns

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sort"

	"github.com/sagernet/sing/common"

	"github.com/miekg/dns"
)

func init() {
	RegisterTransport([]string{"local"}, func(options TransportOptions) (Transport, error) {
		return NewLocalTransport(options), nil
	})
}

var _ Transport = (*LocalTransport)(nil)

type LocalTransport struct {
	name     string
	resolver net.Resolver
}

func NewLocalTransport(options TransportOptions) *LocalTransport {
	return &LocalTransport{
		name: options.Name,
	}
}

func (t *LocalTransport) Name() string {
	return t.name
}

func (t *LocalTransport) Start() error {
	return nil
}

func (t *LocalTransport) Reset() {
}

func (t *LocalTransport) Close() error {
	return nil
}

func (t *LocalTransport) Raw() bool {
	return false
}

func (t *LocalTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	return nil, os.ErrInvalid
}

func (t *LocalTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	var network string
	switch strategy {
	case DomainStrategyAsIS, DomainStrategyPreferIPv4, DomainStrategyPreferIPv6:
		network = "ip"
	case DomainStrategyUseIPv4:
		network = "ip4"
	case DomainStrategyUseIPv6:
		network = "ip6"
	}
	addrs, err := t.resolver.LookupNetIP(ctx, network, domain)
	if err != nil {
		return nil, err
	}
	addrs = common.Map(addrs, func(it netip.Addr) netip.Addr {
		if it.Is4In6() {
			return netip.AddrFrom4(it.As4())
		}
		return it
	})
	switch strategy {
	case DomainStrategyPreferIPv4:
		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].Is4() && addrs[j].Is6()
		})
	case DomainStrategyPreferIPv6:
		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].Is6() && addrs[j].Is4()
		})
	}
	return addrs, nil
}
