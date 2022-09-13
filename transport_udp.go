package dns

import (
	"context"
	"net"
	"net/url"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/miekg/dns"
)

const FixedPacketSize = 4096

var _ Transport = (*UDPTransport)(nil)

func init() {
	RegisterTransport([]string{"udp", ""}, CreateUDPTransport)
}

func CreateUDPTransport(ctx context.Context, dialer N.Dialer, link string) (Transport, error) {
	serverURL, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	if serverURL.Scheme == "" {
		return NewUDPTransport(ctx, dialer, M.ParseSocksaddr(link)), nil
	}
	port := serverURL.Port()
	if port == "" {
		port = "53"
	}
	serverAddr := M.ParseSocksaddrHostPortStr(serverURL.Hostname(), port)
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	return NewUDPTransport(ctx, dialer, serverAddr), nil
}

type UDPTransport struct {
	myTransportAdapter
}

func NewUDPTransport(ctx context.Context, dialer N.Dialer, destination M.Socksaddr) *UDPTransport {
	transport := &UDPTransport{
		newAdapter(ctx, dialer, destination),
	}
	transport.handler = transport
	return transport
}

func (t *UDPTransport) DialContext(ctx context.Context, queryCtx context.Context) (net.Conn, error) {
	return t.dialer.DialContext(ctx, "udp", t.serverAddr)
}

func (t *UDPTransport) ReadMessage(conn net.Conn) (*dns.Msg, error) {
	_buffer := buf.StackNewSize(FixedPacketSize)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	_, err := buffer.ReadOnceFrom(conn)
	if err != nil {
		return nil, err
	}
	var message dns.Msg
	err = message.Unpack(buffer.Bytes())
	return &message, err
}

func (t *UDPTransport) WriteMessage(conn net.Conn, message *dns.Msg) error {
	_buffer := buf.StackNewSize(FixedPacketSize)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	rawMessage, err := message.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return err
	}
	return common.Error(conn.Write(rawMessage))
}
