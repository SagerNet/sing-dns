package dns

import (
	"context"
	"crypto/tls"
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

var _ Transport = (*TLSTransport)(nil)

func init() {
	RegisterTransport([]string{"tls"}, func(options TransportOptions) (Transport, error) {
		return NewTLSTransport(options)
	})
}

type TLSTransport struct {
	myTransportAdapter
}

func NewTLSTransport(options TransportOptions) (*TLSTransport, error) {
	serverURL, err := url.Parse(options.Address)
	if err != nil {
		return nil, err
	}
	serverAddr := M.ParseSocksaddr(serverURL.Host)
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address")
	}
	if serverAddr.Port == 0 {
		serverAddr.Port = 853
	}
	transport := &TLSTransport{
		newAdapter(options, serverAddr),
	}
	transport.handler = transport
	return transport, nil
}

func (t *TLSTransport) DialContext(ctx context.Context) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: t.serverAddr.AddrString(),
	})
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (t *TLSTransport) ReadMessage(conn net.Conn) (*dns.Msg, error) {
	var length uint16
	err := binary.Read(conn, binary.BigEndian, &length)
	if err != nil {
		return nil, err
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

func (t *TLSTransport) WriteMessage(conn net.Conn, message *dns.Msg) error {
	rawMessage, err := message.Pack()
	if err != nil {
		return err
	}
	buffer := buf.NewSize(2 + len(rawMessage))
	defer buffer.Release()
	common.Must(binary.Write(buffer, binary.BigEndian, uint16(len(rawMessage))))
	common.Must1(buffer.Write(rawMessage))
	return common.Error(conn.Write(buffer.Bytes()))
}
