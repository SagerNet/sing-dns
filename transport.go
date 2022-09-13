package dns

import (
	"context"
	"net/netip"
	"net/url"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/miekg/dns"
)

type Transport interface {
	Start() error
	Close() error
	Raw() bool
	Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error)
	Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error)
}

func NewTransport(ctx context.Context, dialer N.Dialer, address string) (Transport, error) {
	if address == "local" {
		return NewLocalTransport(), nil
	}
	serverURL, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	host := serverURL.Hostname()
	if host == "" {
		host = address
	}
	port := serverURL.Port()
	switch serverURL.Scheme {
	case "tls":
		if port == "" {
			port = "853"
		}
	case "quic":
		if port == "" {
			port = "853"
		}
	default:
		if port == "" {
			port = "53"
		}
	}
	destination := M.ParseSocksaddrHostPortStr(host, port)
	switch serverURL.Scheme {
	case "", "udp":
		return NewUDPTransport(ctx, dialer, destination), nil
	case "tcp":
		return NewTCPTransport(ctx, dialer, destination), nil
	case "tls":
		return NewTLSTransport(ctx, dialer, destination), nil
	case "https":
		return NewHTTPSTransport(dialer, serverURL.String()), nil
	case "quic":
		return NewQUICTransport(ctx, dialer, destination)
	case "h3":
		serverURL.Scheme = "https"
		return NewHTTP3Transport(dialer, serverURL.String())
	case "rcode":
		return NewRCodeTransport(serverURL.Host)
	default:
		return nil, E.New("unknown dns scheme: " + serverURL.Scheme)
	}
}
