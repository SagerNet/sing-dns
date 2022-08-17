package dns

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/task"

	"golang.org/x/net/dns/dnsmessage"
)

type myTransportHandler interface {
	DialContext(ctx context.Context, queryCtx context.Context) (net.Conn, error)
	ReadMessage(conn net.Conn) (*dnsmessage.Message, error)
	WriteMessage(conn net.Conn, message *dnsmessage.Message) error
}

type myTransportAdapter struct {
	ctx         context.Context
	cancel      context.CancelFunc
	dialer      N.Dialer
	destination M.Socksaddr
	handler     myTransportHandler
	access      sync.RWMutex
	conn        *dnsConnection
}

func newAdapter(ctx context.Context, dialer N.Dialer, destination M.Socksaddr) myTransportAdapter {
	ctx, cancel := context.WithCancel(ctx)
	return myTransportAdapter{
		ctx:         ctx,
		cancel:      cancel,
		dialer:      dialer,
		destination: destination,
	}
}

func (t *myTransportAdapter) Start() error {
	return nil
}

func (t *myTransportAdapter) open(ctx context.Context) (*dnsConnection, error) {
	connection := t.conn
	if connection != nil {
		if !common.Done(connection.ctx) {
			return connection, nil
		}
	}
	t.access.Lock()
	defer t.access.Unlock()
	connection = t.conn
	if connection != nil {
		if !common.Done(connection.ctx) {
			return connection, nil
		}
	}
	connCtx, cancel := context.WithCancel(t.ctx)
	conn, err := t.handler.DialContext(connCtx, ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	connection = &dnsConnection{
		Conn:      conn,
		ctx:       connCtx,
		cancel:    cancel,
		callbacks: make(map[uint16]chan *dnsmessage.Message),
	}
	go t.recvLoop(connection)
	t.conn = connection
	return connection, nil
}

func (t *myTransportAdapter) recvLoop(conn *dnsConnection) {
	var group task.Group
	group.Append0(func(ctx context.Context) error {
		for {
			message, err := t.handler.ReadMessage(conn)
			if err != nil {
				return err
			}
			conn.access.Lock()
			callback, loaded := conn.callbacks[message.ID]
			if loaded {
				delete(conn.callbacks, message.ID)
			}
			conn.access.Unlock()
			if loaded {
				callback <- message
			}
		}
	})
	group.Cleanup(func() {
		conn.Close()
	})
	group.Run(conn.ctx)
}

func (t *myTransportAdapter) Exchange(ctx context.Context, message *dnsmessage.Message) (*dnsmessage.Message, error) {
	messageId := message.ID
	var response *dnsmessage.Message
	var err error
	for attempts := 0; attempts < 3; attempts++ {
		response, err = t.exchange(ctx, message)
		if err != nil && !common.Done(ctx) {
			continue
		}
		break
	}
	if err == nil {
		response.ID = messageId
	}
	return response, err
}

func (t *myTransportAdapter) exchange(ctx context.Context, message *dnsmessage.Message) (*dnsmessage.Message, error) {
	callback := make(chan *dnsmessage.Message)
	defer close(callback)
	conn, err := t.open(ctx)
	if err != nil {
		return nil, err
	}
	conn.access.Lock()
	conn.queryId++
	message.ID = conn.queryId
	conn.callbacks[message.ID] = callback
	conn.access.Unlock()
	err = t.handler.WriteMessage(conn, message)
	if err != nil {
		conn.cancel()
		return nil, err
	}
	select {
	case response := <-callback:
		return response, nil
	case <-conn.ctx.Done():
		return nil, E.Errors(conn.err, conn.ctx.Err())
	case <-ctx.Done():
		conn.cancel()
		return nil, ctx.Err()
	}
}

func (t *myTransportAdapter) Close() error {
	t.access.Lock()
	defer t.access.Unlock()
	if t.conn != nil {
		t.conn.cancel()
		t.conn.Close()
	}
	return nil
}

func (t *myTransportAdapter) Raw() bool {
	return true
}

func (t *myTransportAdapter) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}

type dnsConnection struct {
	net.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	access    sync.Mutex
	err       error
	queryId   uint16
	callbacks map[uint16]chan *dnsmessage.Message
}
