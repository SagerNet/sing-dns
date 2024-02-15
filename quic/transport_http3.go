package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"

	mDNS "github.com/miekg/dns"
)

var _ dns.Transport = (*HTTP3Transport)(nil)

func init() {
	dns.RegisterTransport([]string{"h3"}, func(options dns.TransportOptions) (dns.Transport, error) {
		return NewHTTP3Transport(options)
	})
}

type HTTP3Transport struct {
	name        string
	destination string
	dialer      *httpDialer
	transport   *http3.RoundTripper
}

func NewHTTP3Transport(options dns.TransportOptions) (*HTTP3Transport, error) {
	serverURL, err := url.Parse(options.Address)
	if err != nil {
		return nil, err
	}
	serverURL.Scheme = "https"
	dialer := &httpDialer{Dialer: options.Dialer}
	return &HTTP3Transport{
		name:        options.Name,
		destination: serverURL.String(),
		dialer:      dialer,
		transport: &http3.RoundTripper{
			Dial: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"dns"},
			},
		},
	}, nil
}

func (t *HTTP3Transport) Name() string {
	return t.name
}

func (t *HTTP3Transport) Start() error {
	return nil
}

func (t *HTTP3Transport) Reset() {
	t.dialer.Reset()
	t.transport.CloseIdleConnections()
}

func (t *HTTP3Transport) Close() error {
	return t.transport.Close()
}

func (t *HTTP3Transport) Raw() bool {
	return true
}

func (t *HTTP3Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
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
	request.Header.Set("content-type", dns.MimeType)
	request.Header.Set("accept", dns.MimeType)

	response, err := t.transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	rawMessage, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var responseMessage mDNS.Msg
	err = responseMessage.Unpack(rawMessage)
	if err != nil {
		return nil, err
	}
	return &responseMessage, nil
}

func (t *HTTP3Transport) Lookup(ctx context.Context, domain string, strategy dns.DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}

type httpDialer struct {
	Dialer      N.Dialer
	access      sync.Mutex
	connections list.List[*httpConnWrapper]
}

func (d *httpDialer) DialContext(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
	destinationAddr := M.ParseSocksaddr(addr)
	conn, dialErr := d.Dialer.DialContext(ctx, N.NetworkUDP, destinationAddr)
	if dialErr != nil {
		return nil, dialErr
	}
	quicConn, err := quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsCfg, cfg)
	if err != nil {
		return nil, err
	}
	wrapper := &httpConnWrapper{EarlyConnection: quicConn, rawConn: conn, dialer: d}
	d.access.Lock()
	element := d.connections.PushFront(wrapper)
	d.access.Unlock()
	wrapper.element = element
	return wrapper, nil
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
	quic.EarlyConnection
	rawConn net.Conn
	dialer  *httpDialer
	element *list.Element[*httpConnWrapper]
}

func (c *httpConnWrapper) Close() error {
	if c.element != nil {
		c.dialer.access.Lock()
		c.dialer.connections.Remove(c.element)
		c.dialer.access.Unlock()
		c.element = nil
	}
	c.EarlyConnection.CloseWithError(0, "")
	return c.rawConn.Close()
}
