package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"

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
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"dns"},
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
}

func (t *HTTPSTransport) Close() error {
	t.Reset()
	return nil
}

func (t *HTTPSTransport) Raw() bool {
	return true
}

func (t *HTTPSTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	message.Id = 0
	rawMessage, err := message.Pack()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.destination, bytes.NewReader(rawMessage))
	if err != nil {
		return nil, err
	}
	request.Header.Set("content-type", MimeType)
	request.Header.Set("accept", MimeType)

	client := &http.Client{Transport: t.transport}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	rawMessage, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var responseMessage dns.Msg
	err = responseMessage.Unpack(rawMessage)
	if err != nil {
		return nil, err
	}
	return &responseMessage, nil
}

func (t *HTTPSTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
