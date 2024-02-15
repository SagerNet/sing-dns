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
	"sync"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"

	"github.com/miekg/dns"
)

const MimeType = "application/dns-message"

var _ Transport = (*HTTPSTransport)(nil)

type HTTPSTransport struct {
	name        string
	destination string
	dialer      *httpDialer
	transport   *http.Transport
}

func init() {
	RegisterTransport([]string{"https"}, func(options TransportOptions) (Transport, error) {
		return NewHTTPSTransport(options), nil
	})
}

func NewHTTPSTransport(options TransportOptions) *HTTPSTransport {
	dialer := &httpDialer{Dialer: options.Dialer}
	return &HTTPSTransport{
		name:        options.Name,
		destination: options.Address,
		dialer:      dialer,
		transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext:       dialer.DialContext,
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
	t.dialer.Reset()
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
	exMessage := *message
	exMessage.Id = 0
	rawMessage, err := exMessage.Pack()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.destination, bytes.NewReader(rawMessage))
	if err != nil {
		return nil, err
	}
	request.Header.Set("content-type", MimeType)
	request.Header.Set("accept", MimeType)
	response, err := t.transport.RoundTrip(request)
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

type httpDialer struct {
	Dialer      N.Dialer
	access      sync.Mutex
	connections list.List[net.Conn]
}

func (d *httpDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
	if err != nil {
		return nil, err
	}
	d.access.Lock()
	element := d.connections.PushFront(conn)
	d.access.Unlock()
	return &httpConnWrapper{conn, d, element}, nil
}

func (d *httpDialer) Reset() {
	d.access.Lock()
	defer d.access.Unlock()
	for element := d.connections.Front(); element != nil; element = element.Next() {
		element.Value.Close()
	}
	d.connections.Init()
}

type httpConnWrapper struct {
	net.Conn
	dialer  *httpDialer
	element *list.Element[net.Conn]
}

func (c *httpConnWrapper) Close() error {
	if c.element != nil {
		c.dialer.access.Lock()
		c.dialer.connections.Remove(c.element)
		c.dialer.access.Unlock()
		c.element = nil
	}
	return c.Conn.Close()
}
