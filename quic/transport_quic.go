package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
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
	dns.RegisterTransport([]string{"quic"}, func(options dns.TransportOptions) (dns.Transport, error) {
		return NewTransport(options)
	})
}

type Transport struct {
	name       string
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr

	access     sync.Mutex
	connection quic.EarlyConnection
}

func NewTransport(options dns.TransportOptions) (*Transport, error) {
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
	return &Transport{
		name:       options.Name,
		ctx:        options.Context,
		dialer:     options.Dialer,
		serverAddr: serverAddr,
	}, nil
}

func (t *Transport) Name() string {
	return t.name
}

func (t *Transport) Start() error {
	return nil
}

func (t *Transport) Reset() {
	connection := t.connection
	if connection != nil {
		connection.CloseWithError(0, "")
	}
}

func (t *Transport) Close() error {
	t.Reset()
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
		t.ctx,
		bufio.NewUnbindPacketConn(conn),
		t.serverAddr.UDPAddr(),
		&tls.Config{ServerName: t.serverAddr.AddrString(), NextProtos: []string{"doq"}},
		nil,
	)
	if err != nil {
		return nil, err
	}
	t.connection = earlyConnection
	return earlyConnection, nil
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	var (
		conn     quic.Connection
		err      error
		response *mDNS.Msg
	)
	for i := 0; i < 2; i++ {
		conn, err = t.openConnection()
		if err != nil {
			return nil, err
		}
		response, err = t.exchange(ctx, message, conn)
		if err == nil {
			return response, nil
		} else if !isQUICRetryError(err) {
			return nil, err
		} else {
			conn.CloseWithError(quic.ApplicationErrorCode(0), "")
			continue
		}
	}
	return nil, err
}

func (t *Transport) exchange(ctx context.Context, message *mDNS.Msg, conn quic.Connection) (*mDNS.Msg, error) {
	exMessage := *message
	exMessage.Id = 0
	requestLen := exMessage.Len()
	buffer := buf.NewSize(3 + requestLen)
	defer buffer.Release()
	common.Must(binary.Write(buffer, binary.BigEndian, uint16(requestLen)))
	rawMessage, err := exMessage.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return nil, err
	}
	buffer.Truncate(2 + len(rawMessage))
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	_, err = stream.Write(buffer.Bytes())
	if err != nil {
		stream.Close()
		return nil, err
	}
	stream.Close()
	buffer.Reset()
	_, err = buffer.ReadFullFrom(stream, 2)
	if err != nil {
		return nil, err
	}
	responseLen := int(binary.BigEndian.Uint16(buffer.Bytes()))
	buffer.Reset()
	if buffer.FreeLen() < responseLen {
		buffer.Release()
		buffer = buf.NewSize(responseLen)
	}
	_, err = buffer.ReadFullFrom(stream, responseLen)
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

// https://github.com/AdguardTeam/dnsproxy/blob/fd1868577652c639cce3da00e12ca548f421baf1/upstream/upstream_quic.go#L394
func isQUICRetryError(err error) (ok bool) {
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) && qAppErr.ErrorCode == 0 {
		return true
	}

	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		return true
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		return true
	}

	return false
}
