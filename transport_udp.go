package dns

import (
	"context"
	"net"
	"net/url"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/miekg/dns"
)

const FixedPacketSize = 16384

var _ Transport = (*UDPTransport)(nil)

func init() {
	RegisterTransport([]string{"udp", ""}, func(options TransportOptions) (Transport, error) {
		return NewUDPTransport(options)
	})
}

type UDPTransport struct {
	myTransportAdapter
	tcpTransport *TCPTransport
	logger       logger.ContextLogger
}

func NewUDPTransport(options TransportOptions) (*UDPTransport, error) {
	var serverAddr M.Socksaddr
	if serverURL, err := url.Parse(options.Address); err != nil || serverURL.Scheme == "" {
		serverAddr = M.ParseSocksaddr(options.Address)
	} else {
		serverAddr = M.ParseSocksaddr(serverURL.Host)
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address")
	}
	if serverAddr.Port == 0 {
		serverAddr.Port = 53
	}
	tcpTransport, err := NewTCPTransport(options)
	if err != nil {
		return nil, err
	}
	transport := &UDPTransport{
		newAdapter(options, serverAddr),
		tcpTransport,
		options.Logger,
	}
	transport.handler = transport
	return transport, nil
}

func (t *UDPTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	response, err := t.myTransportAdapter.Exchange(ctx, message)
	if err != nil {
		return nil, err
	}
	if response.Truncated {
		t.logger.InfoContext(ctx, "response truncated, retrying with TCP")
		return t.tcpTransport.Exchange(ctx, message)
	}
	return response, nil
}

func (t *UDPTransport) DialContext(ctx context.Context) (net.Conn, error) {
	return t.dialer.DialContext(ctx, "udp", t.serverAddr)
}

func (t *UDPTransport) ReadMessage(conn net.Conn) (*dns.Msg, error) {
	buffer := buf.NewSize(FixedPacketSize)
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
	rawMessage, err := message.Pack()
	if err != nil {
		return err
	}
	return common.Error(conn.Write(rawMessage))
}
