package dns

import "net/netip"

type QueryOptions struct {
	Strategy     DomainStrategy
	DisableCache bool
	RewriteTTL   *uint32
	ClientSubnet netip.Prefix
}
