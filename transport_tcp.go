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
	RegisterTransport([]string{"tcp"}, func(options TransportOptions) (Transport, error) {
		return NewTCPTransport(options)
	})
}

type TCPTransport struct {
	myTransportAdapter
}

func NewTCPTransport(options TransportOptions) (*TCPTransport, error) {
	serverURL, err := url.Parse(options.Address)
	if err != nil {
		return nil, err
	}
	serverAddr := M.ParseSocksaddr(serverURL.Host)
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address")
	}
	if serverAddr.Port == 0 {
		serverAddr.Port = 53
	}
	return newTCPTransport(options, serverAddr), nil
}

func newTCPTransport(options TransportOptions, serverAddr M.Socksaddr) *TCPTransport {
	transport := &TCPTransport{
		newAdapter(options, serverAddr, false),
	}
	transport.handler = transport
	return transport
}

func (t *TCPTransport) DialContext(ctx context.Context) (net.Conn, error) {
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
	buffer := buf.NewSize(int(length))
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
	requestLen := message.Len()
	buffer := buf.NewSize(3 + requestLen)
	defer buffer.Release()
	common.Must(binary.Write(buffer, binary.BigEndian, uint16(requestLen)))
	exMessage := *message
	exMessage.Compress = true
	rawMessage, err := exMessage.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return err
	}
	buffer.Truncate(2 + len(rawMessage))
	return common.Error(conn.Write(buffer.Bytes()))
}
