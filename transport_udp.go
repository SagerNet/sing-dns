package dns

import (
	"context"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/dns/dnsmessage"
)

const FixedPacketSize = 4096

var _ Transport = (*UDPTransport)(nil)

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
	return t.dialer.DialContext(ctx, "udp", t.destination)
}

func (t *UDPTransport) ReadMessage(conn net.Conn) (*dnsmessage.Message, error) {
	_buffer := buf.StackNewSize(FixedPacketSize)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	_, err := buffer.ReadOnceFrom(conn)
	if err != nil {
		return nil, err
	}
	var message dnsmessage.Message
	err = message.Unpack(buffer.Bytes())
	return &message, err
}

func (t *UDPTransport) WriteMessage(conn net.Conn, message *dnsmessage.Message) error {
	_buffer := buf.StackNewSize(FixedPacketSize)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	rawMessage, err := message.AppendPack(buffer.Index(0))
	if err != nil {
		return err
	}
	return common.Error(conn.Write(rawMessage))
}
