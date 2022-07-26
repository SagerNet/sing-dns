package test_test

import (
	"context"
	"os"
	"testing"
	"time"

	dns "github.com/sagernet/sing-dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestTCPDNS(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	transport := dns.NewTCPTransport(ctx, N.SystemDialer, M.ParseSocksaddr("1.0.0.1:53"))
	response, err := transport.Exchange(ctx, makeQuery())
	cancel()
	require.NoError(t, err)
	require.NotEmpty(t, response.Answers, "no answers")
	for _, answer := range response.Answers {
		t.Log(answer)
	}
}

func TestTLSDNS(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	transport := dns.NewTLSTransport(ctx, N.SystemDialer, M.ParseSocksaddr("1.0.0.1:853"))
	response, err := transport.Exchange(ctx, makeQuery())
	cancel()
	require.NoError(t, err)
	require.NotEmpty(t, response.Answers, "no answers")
	for _, answer := range response.Answers {
		t.Log(answer)
	}
}

func TestHTTPSDNS(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	transport := dns.NewHTTPSTransport(N.SystemDialer, "https://1.0.0.1/dns-query")
	response, err := transport.Exchange(ctx, makeQuery())
	cancel()
	require.NoError(t, err)
	require.NotEmpty(t, response.Answers, "no answers")
	for _, answer := range response.Answers {
		t.Log(answer)
	}
}

func TestQUICDNS(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	transport, err := dns.NewQUICTransport(ctx, N.SystemDialer, M.ParseSocksaddr("dns.adguard.com:853"))
	if err == os.ErrInvalid {
		t.SkipNow()
		return
	}
	require.NoError(t, err)
	response, err := transport.Exchange(ctx, makeQuery())
	cancel()
	require.NoError(t, err)
	require.NotEmpty(t, response.Answers, "no answers")
	for _, answer := range response.Answers {
		t.Log(answer)
	}
}

func TestH3DNS(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	transport, err := dns.NewHTTP3Transport(N.SystemDialer, "https://8.8.8.8/dns-query")
	if err == os.ErrInvalid {
		t.SkipNow()
		return
	}
	require.NoError(t, err)
	response, err := transport.Exchange(ctx, makeQuery())
	cancel()
	require.NoError(t, err)
	require.NotEmpty(t, response.Answers, "no answers")
	for _, answer := range response.Answers {
		t.Log(answer)
	}
}

func TestUDPDNS(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	transport := dns.NewUDPTransport(ctx, N.SystemDialer, M.ParseSocksaddr("1.0.0.1:53"))
	response, err := transport.Exchange(ctx, makeQuery())
	cancel()
	require.NoError(t, err)
	require.NotEmpty(t, response.Answers, "no answers")
	for _, answer := range response.Answers {
		t.Log(answer)
	}
}

func TestLocalDNS(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	transport := dns.NewLocalTransport()
	response, err := transport.Lookup(ctx, "google.com", dns.DomainStrategyAsIS)
	cancel()
	require.NoError(t, err)
	require.NotEmpty(t, response, "no answers")
	for _, answer := range response {
		t.Log(answer)
	}
}

func makeQuery() *dnsmessage.Message {
	message := &dnsmessage.Message{}
	message.Header.ID = 1
	message.Header.RecursionDesired = true
	message.Questions = append(message.Questions, dnsmessage.Question{
		Name:  dnsmessage.MustNewName("google.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	return message
}
