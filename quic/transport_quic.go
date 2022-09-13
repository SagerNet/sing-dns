package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net/netip"
	"net/url"
	"os"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var _ dns.Transport = (*Transport)(nil)

func init() {
	dns.RegisterTransport([]string{"quic"}, CreateTransport)
}

func CreateTransport(ctx context.Context, dialer N.Dialer, link string) (dns.Transport, error) {
	serverURL, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port := serverURL.Port()
	if port == "" {
		port = "853"
	}
	serverAddr := M.ParseSocksaddrHostPortStr(serverURL.Hostname(), port)
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	return NewTransport(ctx, dialer, serverAddr)
}

type Transport struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr

	access     sync.Mutex
	connection quic.EarlyConnection
}

func NewTransport(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr) (*Transport, error) {
	return &Transport{
		ctx:        ctx,
		dialer:     dialer,
		serverAddr: serverAddr,
	}, nil
}

func (t *Transport) Start() error {
	return nil
}

func (t *Transport) Close() error {
	connection := t.connection
	if connection != nil {
		connection.CloseWithError(0, "")
	}
	return nil
}

func (t *Transport) Raw() bool {
	return true
}

func (t *Transport) openConnection() (quic.EarlyConnection, error) {
	connection := t.connection
	if connection != nil && !common.Done(connection.Context()) {
		return connection, nil
	}
	t.access.Lock()
	defer t.access.Unlock()
	connection = t.connection
	if connection != nil && !common.Done(connection.Context()) {
		return connection, nil
	}
	conn, err := t.dialer.DialContext(t.ctx, N.NetworkUDP, t.serverAddr)
	if err != nil {
		return nil, err
	}
	earlyConnection, err := quic.DialEarly(
		bufio.NewUnbindPacketConn(conn),
		t.serverAddr.UDPAddr(),
		t.serverAddr.AddrString(),
		&tls.Config{NextProtos: []string{"doq"}},
		nil,
	)
	if err != nil {
		return nil, err
	}
	t.connection = earlyConnection
	return earlyConnection, nil
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	message.Id = 0
	_buffer := buf.StackNewSize(dns.FixedPacketSize)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	buffer.Resize(2, 0)
	rawMessage, err := message.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return nil, err
	}
	messageLen := len(rawMessage)
	buffer.Truncate(messageLen)
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(messageLen))
	conn, err := t.openConnection()
	if conn == nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	_, err = stream.Write(buffer.Bytes())
	if err != nil {
		return nil, err
	}
	buffer.FullReset()
	_, err = buffer.ReadFullFrom(stream, 2)
	if err != nil {
		return nil, err
	}
	messageLen = int(binary.BigEndian.Uint16(buffer.Bytes()))
	buffer.FullReset()
	_, err = buffer.ReadFullFrom(stream, messageLen)
	if err != nil {
		return nil, err
	}
	var responseMessage mDNS.Msg
	err = responseMessage.Unpack(buffer.Bytes())
	if err != nil {
		return nil, err
	}
	return &responseMessage, nil
}

func (t *Transport) Lookup(ctx context.Context, domain string, strategy dns.DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
