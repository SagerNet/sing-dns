package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/dns/dnsmessage"
)

var _ Transport = (*TLSTransport)(nil)

type TLSTransport struct {
	myTransportAdapter
}

func NewTLSTransport(ctx context.Context, dialer N.Dialer, destination M.Socksaddr) *TLSTransport {
	transport := &TLSTransport{
		newAdapter(ctx, dialer, destination),
	}
	transport.handler = transport
	return transport
}

func (t *TLSTransport) DialContext(ctx context.Context, queryCtx context.Context) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.destination)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: t.destination.AddrString(),
	})
	err = tlsConn.HandshakeContext(queryCtx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (t *TLSTransport) ReadMessage(conn net.Conn) (*dnsmessage.Message, error) {
	var length uint16
	err := binary.Read(conn, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	_buffer := buf.StackNewSize(int(length))
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	_, err = buffer.ReadFullFrom(conn, int(length))
	if err != nil {
		return nil, err
	}
	var message dnsmessage.Message
	err = message.Unpack(buffer.Bytes())
	return &message, err
}

func (t *TLSTransport) WriteMessage(conn net.Conn, message *dnsmessage.Message) error {
	_buffer := buf.StackNewSize(4096)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	buffer.Resize(2, 0)
	rawMessage, err := message.AppendPack(buffer.Index(0))
	if err != nil {
		return err
	}
	buffer.Resize(0, 2+len(rawMessage))
	binary.BigEndian.PutUint16(buffer.To(2), uint16(len(rawMessage)))
	return common.Error(conn.Write(buffer.Bytes()))
}
