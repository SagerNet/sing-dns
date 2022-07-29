//go:build with_quic

package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net/netip"
	"os"
	"sync"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/lucas-clemente/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

var _ Transport = (*QUICTransport)(nil)

type QUICTransport struct {
	ctx         context.Context
	dialer      N.Dialer
	destination M.Socksaddr

	access     sync.Mutex
	connection quic.EarlyConnection
}

func NewQUICTransport(ctx context.Context, dialer N.Dialer, destination M.Socksaddr) (*QUICTransport, error) {
	return &QUICTransport{
		ctx:         ctx,
		dialer:      dialer,
		destination: destination,
	}, nil
}

func (t *QUICTransport) Start() error {
	return nil
}

func (t *QUICTransport) Close() error {
	connection := t.connection
	if connection != nil {
		connection.CloseWithError(0, "")
	}
	return nil
}

func (t *QUICTransport) Raw() bool {
	return true
}

func (t *QUICTransport) openConnection() (quic.EarlyConnection, error) {
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
	conn, err := t.dialer.DialContext(t.ctx, N.NetworkUDP, t.destination)
	if err != nil {
		return nil, err
	}
	earlyConnection, err := quic.DialEarly(
		bufio.NewUnbindPacketConn(conn),
		t.destination.UDPAddr(),
		t.destination.AddrString(),
		&tls.Config{NextProtos: []string{"doq"}},
		nil,
	)
	if err != nil {
		return nil, err
	}
	t.connection = earlyConnection
	return earlyConnection, nil
}

func (t *QUICTransport) Exchange(ctx context.Context, message *dnsmessage.Message) (*dnsmessage.Message, error) {
	message.ID = 0
	_buffer := buf.StackNewSize(1024)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	buffer.Resize(2, 0)
	rawMessage, err := message.AppendPack(buffer.Index(0))
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
	var responseMessage dnsmessage.Message
	err = responseMessage.Unpack(buffer.Bytes())
	if err != nil {
		return nil, err
	}
	return &responseMessage, nil
}

func (t *QUICTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
