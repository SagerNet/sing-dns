//go:build with_quic

package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/netip"
	"os"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"golang.org/x/net/dns/dnsmessage"
)

var _ Transport = (*HTTP3Transport)(nil)

type HTTP3Transport struct {
	destination string
	transport   *http3.RoundTripper
}

func NewHTTP3Transport(dialer N.Dialer, destination string) (*HTTP3Transport, error) {
	return &HTTP3Transport{
		destination: destination,
		transport: &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				destinationAddr := M.ParseSocksaddr(addr)
				conn, err := dialer.DialContext(ctx, N.NetworkUDP, destinationAddr)
				if err != nil {
					return nil, err
				}
				return quic.DialEarlyContext(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), destinationAddr.AddrString(), tlsCfg, cfg)
			},
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"dns"},
			},
		},
	}, nil
}

func (t *HTTP3Transport) Start() error {
	return nil
}

func (t *HTTP3Transport) Close() error {
	return t.transport.Close()
}

func (t *HTTP3Transport) Raw() bool {
	return true
}

func (t *HTTP3Transport) Exchange(ctx context.Context, message *dnsmessage.Message) (*dnsmessage.Message, error) {
	message.ID = 0
	_buffer := buf.StackNewSize(1024)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	rawMessage, err := message.AppendPack(buffer.Index(0))
	if err != nil {
		return nil, err
	}
	buffer.Truncate(len(rawMessage))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.destination, bytes.NewReader(buffer.Bytes()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("content-type", dnsMimeType)
	request.Header.Set("accept", dnsMimeType)

	client := &http.Client{Transport: t.transport}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	buffer.FullReset()
	_, err = buffer.ReadFrom(response.Body)
	if err != nil {
		return nil, err
	}
	var responseMessage dnsmessage.Message
	err = responseMessage.Unpack(buffer.Bytes())
	if err != nil {
		return nil, err
	}
	return &responseMessage, nil
}

func (t *HTTP3Transport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
