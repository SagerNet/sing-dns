package dns

import (
	"context"
	"encoding/binary"
	"net"
	"net/url"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/miekg/dns"
)

var _ Transport = (*TCPTransport)(nil)

func init() {
	RegisterTransport([]string{"tcp"}, CreateTCPTransport)
}

func CreateTCPTransport(ctx context.Context, dialer N.Dialer, link string) (Transport, error) {
	serverURL, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	return NewTCPTransport(ctx, dialer, M.ParseSocksaddr(serverURL.Host))
}

type TCPTransport struct {
	myTransportAdapter
}

func NewTCPTransport(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr) (*TCPTransport, error) {
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address")
	}
	if serverAddr.Port == 0 {
		serverAddr.Port = 53
	}
	transport := &TCPTransport{
		newAdapter(ctx, dialer, serverAddr),
	}
	transport.handler = transport
	return transport, nil
}

func (t *TCPTransport) DialContext(ctx context.Context, queryCtx context.Context) (net.Conn, error) {
	return t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
}

func (t *TCPTransport) ReadMessage(conn net.Conn) (*dns.Msg, error) {
	var length uint16
	err := binary.Read(conn, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 10 {
		return nil, dns.ErrShortRead
	}
	_buffer := buf.StackNewSize(int(length))
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	_, err = buffer.ReadFullFrom(conn, int(length))
	if err != nil {
		return nil, err
	}
	var message dns.Msg
	err = message.Unpack(buffer.Bytes())
	return &message, err
}

func (t *TCPTransport) WriteMessage(conn net.Conn, message *dns.Msg) error {
	_buffer := buf.StackNewSize(FixedPacketSize)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	buffer.Resize(2, 0)
	rawMessage, err := message.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return err
	}
	buffer.Resize(0, 2+len(rawMessage))
	binary.BigEndian.PutUint16(buffer.To(2), uint16(len(rawMessage)))
	return common.Error(conn.Write(buffer.Bytes()))
}
