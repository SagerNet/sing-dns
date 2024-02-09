package dns

import (
	"context"
	"net/netip"
	"net/url"
	"os"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/miekg/dns"
)

var _ Transport = (*RCodeTransport)(nil)

func init() {
	RegisterTransport([]string{"rcode"}, func(options TransportOptions) (Transport, error) {
		return NewRCodeTransport(options)
	})
}

type RCodeTransport struct {
	name string
	code RCodeError
}

func NewRCodeTransport(options TransportOptions) (*RCodeTransport, error) {
	serverURL, err := url.Parse(options.Address)
	if err != nil {
		return nil, err
	}
	switch serverURL.Host {
	case "success":
		return &RCodeTransport{options.Name, RCodeSuccess}, nil
	case "format_error":
		return &RCodeTransport{options.Name, RCodeFormatError}, nil
	case "server_failure":
		return &RCodeTransport{options.Name, RCodeServerFailure}, nil
	case "name_error":
		return &RCodeTransport{options.Name, RCodeNameError}, nil
	case "not_implemented":
		return &RCodeTransport{options.Name, RCodeNotImplemented}, nil
	case "refused":
		return &RCodeTransport{options.Name, RCodeRefused}, nil
	default:
		return nil, E.New("unknown rcode: " + options.Name)
	}
}

func (t *RCodeTransport) Name() string {
	return t.name
}

func (t *RCodeTransport) Start() error {
	return nil
}

func (t *RCodeTransport) Reset() {
}

func (t *RCodeTransport) Close() error {
	return nil
}

func (t *RCodeTransport) Raw() bool {
	return true
}

func (t *RCodeTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	message.Response = true
	message.Rcode = int(t.code)
	return message, nil
}

func (t *RCodeTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
