package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

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
	transport   *http3.RoundTripper
}

func NewHTTP3Transport(options dns.TransportOptions) (*HTTP3Transport, error) {
	serverURL, err := url.Parse(options.Address)
	if err != nil {
		return nil, err
	}
	serverURL.Scheme = "https"
	return &HTTP3Transport{
		name:        options.Name,
		destination: serverURL.String(),
		transport: &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				destinationAddr := M.ParseSocksaddr(addr)
				conn, dialErr := options.Dialer.DialContext(ctx, N.NetworkUDP, destinationAddr)
				if dialErr != nil {
					return nil, dialErr
				}
				return quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsCfg, cfg)
			},
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
