package dns

import (
	"context"
	"crypto/tls"
	"net/netip"
	"net/url"
	"os"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"

	"github.com/miekg/dns"
)

var _ Transport = (*TLSTransport)(nil)

func init() {
	RegisterTransport([]string{"tls"}, func(options TransportOptions) (Transport, error) {
		return NewTLSTransport(options)
	})
}

type TLSTransport struct {
	name        string
	dialer      N.Dialer
	logger      logger.ContextLogger
	serverAddr  M.Socksaddr
	access      sync.Mutex
	connections list.List[*tlsDNSConn]
}

type tlsDNSConn struct {
	*tls.Conn
	queryId uint16
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
	return newTLSTransport(options, serverAddr), nil
}

func newTLSTransport(options TransportOptions, serverAddr M.Socksaddr) *TLSTransport {
	return &TLSTransport{
		name:       options.Name,
		dialer:     options.Dialer,
		logger:     options.Logger,
		serverAddr: serverAddr,
	}
}

func (t *TLSTransport) Name() string {
	return t.name
}

func (t *TLSTransport) Start() error {
	return nil
}

func (t *TLSTransport) Reset() {
	t.access.Lock()
	defer t.access.Unlock()
	for connection := t.connections.Front(); connection != nil; connection = connection.Next() {
		connection.Value.Close()
	}
	t.connections.Init()
}

func (t *TLSTransport) Close() error {
	t.Reset()
	return nil
}

func (t *TLSTransport) Raw() bool {
	return true
}

func (t *TLSTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	t.access.Lock()
	conn := t.connections.PopFront()
	t.access.Unlock()
	if conn == nil {
		tcpConn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(tcpConn, &tls.Config{
			ServerName: t.serverAddr.AddrString(),
		})
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		conn = &tlsDNSConn{Conn: tlsConn}
	}
	messageId := message.Id
	conn.queryId++
	message.Id = conn.queryId
	err := writeMessage(conn, message)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "write request")
	}
	response, err := readMessage(conn)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "read response")
	}
	response.Id = messageId
	t.access.Lock()
	t.connections.PushBack(conn)
	t.access.Unlock()
	return response, nil
}

func (t *TLSTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
