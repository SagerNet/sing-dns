package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"net/url"
	"os"

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
	name       string
	dialer     N.Dialer
	serverAddr M.Socksaddr
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
	return &TCPTransport{
		name:       options.Name,
		dialer:     options.Dialer,
		serverAddr: serverAddr,
	}
}

func (t *TCPTransport) Name() string {
	return t.name
}

func (t *TCPTransport) Start() error {
	return nil
}

func (t *TCPTransport) Reset() {
}

func (t *TCPTransport) Close() error {
	return nil
}

func (t *TCPTransport) Raw() bool {
	return true
}

func (t *TCPTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	err = writeMessage(conn, message)
	if err != nil {
		return nil, err
	}
	return readMessage(conn)
}

func (t *TCPTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}

func readMessage(reader io.Reader) (*dns.Msg, error) {
	var responseLen uint16
	err := binary.Read(reader, binary.BigEndian, &responseLen)
	if err != nil {
		return nil, err
	}
	if responseLen < 10 {
		return nil, dns.ErrShortRead
	}
	buffer := buf.NewSize(int(responseLen))
	defer buffer.Release()
	_, err = buffer.ReadFullFrom(reader, int(responseLen))
	if err != nil {
		return nil, err
	}
	var message dns.Msg
	err = message.Unpack(buffer.Bytes())
	return &message, err
}

func writeMessage(writer io.Writer, message *dns.Msg) error {
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
	return common.Error(writer.Write(buffer.Bytes()))
}
