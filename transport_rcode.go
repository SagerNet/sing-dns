package dns

import (
	"context"
	"net/netip"
	"os"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/dns/dnsmessage"
)

var _ Transport = (*RCodeTransport)(nil)

type RCodeTransport struct {
	code RCodeError
}

func NewRCodeTransport(code string) (*RCodeTransport, error) {
	switch code {
	case "success":
		return &RCodeTransport{RCodeSuccess}, nil
	case "format_error":
		return &RCodeTransport{RCodeFormatError}, nil
	case "server_failure":
		return &RCodeTransport{RCodeServerFailure}, nil
	case "name_error":
		return &RCodeTransport{RCodeNameError}, nil
	case "not_implemented":
		return &RCodeTransport{RCodeNotImplemented}, nil
	case "refused":
		return &RCodeTransport{RCodeRefused}, nil
	default:
		return nil, E.New("unknown rcode: " + code)
	}
}

func (t *RCodeTransport) Start() error {
	return nil
}

func (t *RCodeTransport) Close() error {
	return nil
}

func (t *RCodeTransport) Raw() bool {
	return true
}

func (t *RCodeTransport) Exchange(ctx context.Context, message *dnsmessage.Message) (*dnsmessage.Message, error) {
	message.Response = true
	message.RCode = dnsmessage.RCode(t.code)
	return message, nil
}

func (t *RCodeTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
