package dns

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/miekg/dns"
)

const MimeType = "application/dns-message"

var _ Transport = (*HTTPSTransport)(nil)

type HTTPSTransport struct {
	name        string
	destination string
	transport   *http.Transport
}

func init() {
	RegisterTransport([]string{"https"}, func(options TransportOptions) (Transport, error) {
		return NewHTTPSTransport(options), nil
	})
}

func NewHTTPSTransport(options TransportOptions) *HTTPSTransport {
	return &HTTPSTransport{
		name:        options.Name,
		destination: options.Address,
		transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return options.Dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}
}

func (t *HTTPSTransport) Name() string {
	return t.name
}

func (t *HTTPSTransport) Start() error {
	return nil
}

func (t *HTTPSTransport) Reset() {
	t.transport.CloseIdleConnections()
	t.transport = t.transport.Clone()
}

func (t *HTTPSTransport) Close() error {
	t.Reset()
	return nil
}

func (t *HTTPSTransport) Raw() bool {
	return true
}

func (t *HTTPSTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	exMessage := *message
	exMessage.Id = 0
	exMessage.Compress = true
	requestBuffer := buf.NewSize(1 + message.Len())
	rawMessage, err := exMessage.PackBuffer(requestBuffer.FreeBytes())
	if err != nil {
		requestBuffer.Release()
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.destination, bytes.NewReader(rawMessage))
	if err != nil {
		requestBuffer.Release()
		return nil, err
	}
	request.Header.Set("Content-Type", MimeType)
	request.Header.Set("Accept", MimeType)
	response, err := t.transport.RoundTrip(request)
	requestBuffer.Release()
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, E.New("unexpected status: ", response.Status)
	}
	var responseMessage dns.Msg
	if response.ContentLength > 0 {
		responseBuffer := buf.NewSize(int(response.ContentLength))
		_, err = responseBuffer.ReadFullFrom(response.Body, int(response.ContentLength))
		if err != nil {
			return nil, err
		}
		err = responseMessage.Unpack(responseBuffer.Bytes())
		responseBuffer.Release()
	} else {
		rawMessage, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		err = responseMessage.Unpack(rawMessage)
	}
	if err != nil {
		return nil, err
	}
	return &responseMessage, nil
}

func (t *HTTPSTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
