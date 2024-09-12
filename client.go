package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/task"

	"github.com/miekg/dns"
)

const (
	DefaultTTL     = 600
	DefaultTimeout = 10 * time.Second
)

var (
	ErrNoRawSupport           = E.New("no raw query support by current transport")
	ErrNotCached              = E.New("not cached")
	ErrResponseRejected       = E.New("response rejected")
	ErrResponseRejectedCached = E.Extend(ErrResponseRejected, "cached")
)

type Client struct {
	timeout          time.Duration
	disableCache     bool
	disableExpire    bool
	independentCache bool
	rdrc             RDRCStore
	initRDRCFunc     func() RDRCStore
	logger           logger.ContextLogger
	cache            *cache.LruCache[dns.Question, *dns.Msg]
	transportCache   *cache.LruCache[transportCacheKey, *dns.Msg]
}

type RDRCStore interface {
	LoadRDRC(transportName string, qName string, qType uint16) (rejected bool)
	SaveRDRC(transportName string, qName string, qType uint16) error
	SaveRDRCAsync(transportName string, qName string, qType uint16, logger logger.Logger)
}

type transportCacheKey struct {
	dns.Question
	transportName string
}

type ClientOptions struct {
	Timeout          time.Duration
	DisableCache     bool
	DisableExpire    bool
	IndependentCache bool
	RDRC             func() RDRCStore
	Logger           logger.ContextLogger
}

func NewClient(options ClientOptions) *Client {
	client := &Client{
		timeout:          options.Timeout,
		disableCache:     options.DisableCache,
		disableExpire:    options.DisableExpire,
		independentCache: options.IndependentCache,
		initRDRCFunc:     options.RDRC,
		logger:           options.Logger,
	}
	if client.timeout == 0 {
		client.timeout = DefaultTimeout
	}
	if !client.disableCache {
		if !client.independentCache {
			client.cache = cache.New[dns.Question, *dns.Msg]()
		} else {
			client.transportCache = cache.New[transportCacheKey, *dns.Msg]()
		}
	}
	return client
}

func (c *Client) Start() {
	if c.initRDRCFunc != nil {
		c.rdrc = c.initRDRCFunc()
	}
}

func (c *Client) Exchange(ctx context.Context, transport Transport, message *dns.Msg, strategy DomainStrategy) (*dns.Msg, error) {
	return c.ExchangeWithResponseCheck(ctx, transport, message, strategy, nil)
}

func (c *Client) ExchangeWithResponseCheck(ctx context.Context, transport Transport, message *dns.Msg, strategy DomainStrategy, responseChecker func(response *dns.Msg) bool) (*dns.Msg, error) {
	if len(message.Question) == 0 {
		if c.logger != nil {
			c.logger.WarnContext(ctx, "bad question size: ", len(message.Question))
		}
		responseMessage := dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       message.Id,
				Response: true,
				Rcode:    dns.RcodeFormatError,
			},
			Question: message.Question,
		}
		return &responseMessage, nil
	}
	question := message.Question[0]
	clientSubnet, clientSubnetLoaded := ClientSubnetFromContext(ctx)
	if clientSubnetLoaded {
		message = SetClientSubnet(message, clientSubnet, true)
	}
	isSimpleRequest := len(message.Question) == 1 &&
		len(message.Ns) == 0 &&
		len(message.Extra) == 0 &&
		!clientSubnetLoaded
	disableCache := !isSimpleRequest || c.disableCache || DisableCacheFromContext(ctx)
	if !disableCache {
		response, ttl := c.loadResponse(question, transport)
		if response != nil {
			logCachedResponse(c.logger, ctx, response, ttl)
			response.Id = message.Id
			return response, nil
		}
	}
	if question.Qtype == dns.TypeA && strategy == DomainStrategyUseIPv6 || question.Qtype == dns.TypeAAAA && strategy == DomainStrategyUseIPv4 {
		responseMessage := dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       message.Id,
				Response: true,
				Rcode:    dns.RcodeSuccess,
			},
			Question: []dns.Question{question},
		}
		if c.logger != nil {
			c.logger.DebugContext(ctx, "strategy rejected")
		}
		return &responseMessage, nil
	}
	if !transport.Raw() {
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			return c.exchangeToLookup(ctx, transport, message, question)
		}
		return nil, ErrNoRawSupport
	}
	messageId := message.Id
	contextTransport, clientSubnetLoaded := transportNameFromContext(ctx)
	if clientSubnetLoaded && transport.Name() == contextTransport {
		return nil, E.New("DNS query loopback in transport[", contextTransport, "]")
	}
	ctx = contextWithTransportName(ctx, transport.Name())
	if responseChecker != nil && c.rdrc != nil {
		rejected := c.rdrc.LoadRDRC(transport.Name(), question.Name, question.Qtype)
		if rejected {
			return nil, ErrResponseRejectedCached
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	response, err := transport.Exchange(ctx, message)
	cancel()
	if err != nil {
		return nil, err
	}
	if responseChecker != nil && !responseChecker(response) {
		if c.rdrc != nil {
			c.rdrc.SaveRDRCAsync(transport.Name(), question.Name, question.Qtype, c.logger)
		}
		return response, ErrResponseRejected
	}
	if question.Qtype == dns.TypeHTTPS {
		if strategy == DomainStrategyUseIPv4 || strategy == DomainStrategyUseIPv6 {
			for _, rr := range response.Answer {
				https, isHTTPS := rr.(*dns.HTTPS)
				if !isHTTPS {
					continue
				}
				content := https.SVCB
				content.Value = common.Filter(content.Value, func(it dns.SVCBKeyValue) bool {
					if strategy == DomainStrategyUseIPv4 {
						return it.Key() != dns.SVCB_IPV6HINT
					} else {
						return it.Key() != dns.SVCB_IPV4HINT
					}
				})
				https.SVCB = content
			}
		}
	}
	var timeToLive int
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if timeToLive == 0 || record.Header().Ttl > 0 && int(record.Header().Ttl) < timeToLive {
				timeToLive = int(record.Header().Ttl)
			}
		}
	}
	if rewriteTTL, loaded := RewriteTTLFromContext(ctx); loaded {
		timeToLive = int(rewriteTTL)
	}
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if record.Header().Rrtype == dns.TypeOPT {
				// The Ttl field of the OPT record is used to store the extended RCode
				// and the edns0 version number.
				continue
			}
			record.Header().Ttl = uint32(timeToLive)
		}
	}
	response.Id = messageId
	if !disableCache {
		c.storeCache(transport, question, response, timeToLive)
	}
	logExchangedResponse(c.logger, ctx, response, timeToLive)
	return response, err
}

func (c *Client) Lookup(ctx context.Context, transport Transport, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return c.LookupWithResponseCheck(ctx, transport, domain, strategy, nil)
}

func (c *Client) LookupWithResponseCheck(ctx context.Context, transport Transport, domain string, strategy DomainStrategy, responseChecker func(responseAddrs []netip.Addr) bool) ([]netip.Addr, error) {
	if dns.IsFqdn(domain) {
		domain = domain[:len(domain)-1]
	}
	dnsName := dns.Fqdn(domain)
	if transport.Raw() {
		if strategy == DomainStrategyUseIPv4 {
			return c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, strategy, responseChecker)
		} else if strategy == DomainStrategyUseIPv6 {
			return c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, strategy, responseChecker)
		}
		var response4 []netip.Addr
		var response6 []netip.Addr
		var group task.Group
		group.Append("exchange4", func(ctx context.Context) error {
			response, err := c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, strategy, responseChecker)
			if err != nil {
				return err
			}
			response4 = response
			return nil
		})
		group.Append("exchange6", func(ctx context.Context) error {
			response, err := c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, strategy, responseChecker)
			if err != nil {
				return err
			}
			response6 = response
			return nil
		})
		err := group.Run(ctx)
		if len(response4) == 0 && len(response6) == 0 {
			return nil, err
		}
		return sortAddresses(response4, response6, strategy), nil
	}
	disableCache := c.disableCache || DisableCacheFromContext(ctx)
	if !disableCache {
		if strategy == DomainStrategyUseIPv4 {
			response, err := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}, transport)
			if err != ErrNotCached {
				return response, err
			}
		} else if strategy == DomainStrategyUseIPv6 {
			response, err := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}, transport)
			if err != ErrNotCached {
				return response, err
			}
		} else {
			response4, _ := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}, transport)
			response6, _ := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}, transport)
			if len(response4) > 0 || len(response6) > 0 {
				return sortAddresses(response4, response6, strategy), nil
			}
		}
	}
	if responseChecker != nil && c.rdrc != nil {
		var rejected bool
		if strategy != DomainStrategyUseIPv6 {
			rejected = c.rdrc.LoadRDRC(transport.Name(), dnsName, dns.TypeA)
		}
		if !rejected && strategy != DomainStrategyUseIPv4 {
			rejected = c.rdrc.LoadRDRC(transport.Name(), dnsName, dns.TypeAAAA)
		}
		if rejected {
			return nil, ErrResponseRejectedCached
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	var rCode int
	response, err := transport.Lookup(ctx, domain, strategy)
	cancel()
	if err != nil {
		return nil, wrapError(err)
	}
	if responseChecker != nil && !responseChecker(response) {
		if c.rdrc != nil {
			if common.Any(response, func(addr netip.Addr) bool {
				return addr.Is4()
			}) {
				c.rdrc.SaveRDRCAsync(transport.Name(), dnsName, dns.TypeA, c.logger)
			}
			if common.Any(response, func(addr netip.Addr) bool {
				return addr.Is6()
			}) {
				c.rdrc.SaveRDRCAsync(transport.Name(), dnsName, dns.TypeAAAA, c.logger)
			}
		}
		return response, ErrResponseRejected
	}
	header := dns.MsgHdr{
		Response: true,
		Rcode:    rCode,
	}
	if !disableCache {
		var timeToLive uint32
		if rewriteTTL, loaded := RewriteTTLFromContext(ctx); loaded {
			timeToLive = rewriteTTL
		} else {
			timeToLive = DefaultTTL
		}
		if strategy != DomainStrategyUseIPv6 {
			question4 := dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			response4 := common.Filter(response, func(addr netip.Addr) bool {
				return addr.Is4() || addr.Is4In6()
			})
			message4 := &dns.Msg{
				MsgHdr:   header,
				Question: []dns.Question{question4},
			}
			if len(response4) > 0 {
				for _, address := range response4 {
					message4.Answer = append(message4.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   question4.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    timeToLive,
						},
						A: address.AsSlice(),
					})
				}
			}
			c.storeCache(transport, question4, message4, int(timeToLive))
		}
		if strategy != DomainStrategyUseIPv4 {
			question6 := dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}
			response6 := common.Filter(response, func(addr netip.Addr) bool {
				return addr.Is6() && !addr.Is4In6()
			})
			message6 := &dns.Msg{
				MsgHdr:   header,
				Question: []dns.Question{question6},
			}
			if len(response6) > 0 {
				for _, address := range response6 {
					message6.Answer = append(message6.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   question6.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    DefaultTTL,
						},
						AAAA: address.AsSlice(),
					})
				}
			}
			c.storeCache(transport, question6, message6, int(timeToLive))
		}
	}
	return response, nil
}

func (c *Client) ClearCache() {
	if c.cache != nil {
		c.cache.Clear()
	}
	if c.transportCache != nil {
		c.transportCache.Clear()
	}
}

func (c *Client) LookupCache(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, bool) {
	if c.independentCache {
		return nil, false
	}
	disableCache := c.disableCache || DisableCacheFromContext(ctx)
	if disableCache {
		return nil, false
	}
	if dns.IsFqdn(domain) {
		domain = domain[:len(domain)-1]
	}
	dnsName := dns.Fqdn(domain)
	if strategy == DomainStrategyUseIPv4 {
		response, err := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}, nil)
		if err != ErrNotCached {
			return response, true
		}
	} else if strategy == DomainStrategyUseIPv6 {
		response, err := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeAAAA,
			Qclass: dns.ClassINET,
		}, nil)
		if err != ErrNotCached {
			return response, true
		}
	} else {
		response4, _ := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}, nil)
		response6, _ := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeAAAA,
			Qclass: dns.ClassINET,
		}, nil)
		if len(response4) > 0 || len(response6) > 0 {
			return sortAddresses(response4, response6, strategy), true
		}
	}
	return nil, false
}

func (c *Client) ExchangeCache(ctx context.Context, message *dns.Msg) (*dns.Msg, bool) {
	if c.independentCache || len(message.Question) != 1 {
		return nil, false
	}
	question := message.Question[0]
	_, clientSubnetLoaded := transportNameFromContext(ctx)
	isSimpleRequest := len(message.Question) == 1 &&
		len(message.Ns) == 0 &&
		len(message.Extra) == 0 &&
		!clientSubnetLoaded
	disableCache := !isSimpleRequest || c.disableCache || DisableCacheFromContext(ctx)
	if disableCache {
		return nil, false
	}
	response, ttl := c.loadResponse(question, nil)
	if response == nil {
		return nil, false
	}
	logCachedResponse(c.logger, ctx, response, ttl)
	response.Id = message.Id
	return response, true
}

func sortAddresses(response4 []netip.Addr, response6 []netip.Addr, strategy DomainStrategy) []netip.Addr {
	if strategy == DomainStrategyPreferIPv6 {
		return append(response6, response4...)
	} else {
		return append(response4, response6...)
	}
}

func (c *Client) storeCache(transport Transport, question dns.Question, message *dns.Msg, timeToLive int) {
	if timeToLive == 0 {
		return
	}
	if c.disableExpire {
		if !c.independentCache {
			c.cache.Store(question, message)
		} else {
			c.transportCache.Store(transportCacheKey{
				Question:      question,
				transportName: transport.Name(),
			}, message)
		}
		return
	}
	expireAt := time.Now().Add(time.Second * time.Duration(timeToLive))
	if !c.independentCache {
		c.cache.StoreWithExpire(question, message, expireAt)
	} else {
		c.transportCache.StoreWithExpire(transportCacheKey{
			Question:      question,
			transportName: transport.Name(),
		}, message, expireAt)
	}
}

func (c *Client) exchangeToLookup(ctx context.Context, transport Transport, message *dns.Msg, question dns.Question) (*dns.Msg, error) {
	domain := question.Name
	var strategy DomainStrategy
	if question.Qtype == dns.TypeA {
		strategy = DomainStrategyUseIPv4
	} else {
		strategy = DomainStrategyUseIPv6
	}
	result, err := c.Lookup(ctx, transport, domain, strategy)
	if err != nil {
		return nil, wrapError(err)
	}
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       message.Id,
			Rcode:    dns.RcodeSuccess,
			Response: true,
		},
		Question: message.Question,
	}
	var timeToLive uint32
	if rewriteTTL, loaded := RewriteTTLFromContext(ctx); loaded {
		timeToLive = rewriteTTL
	} else {
		timeToLive = DefaultTTL
	}
	for _, address := range result {
		if address.Is4In6() {
			address = netip.AddrFrom4(address.As4())
		}
		if address.Is4() {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				A: address.AsSlice(),
			})
		} else {
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				AAAA: address.AsSlice(),
			})
		}
	}
	return &response, nil
}

func (c *Client) lookupToExchange(ctx context.Context, transport Transport, name string, qType uint16, strategy DomainStrategy, responseChecker func(responseAddrs []netip.Addr) bool) ([]netip.Addr, error) {
	question := dns.Question{
		Name:   name,
		Qtype:  qType,
		Qclass: dns.ClassINET,
	}
	disableCache := c.disableCache || DisableCacheFromContext(ctx)
	if !disableCache {
		cachedAddresses, err := c.questionCache(question, transport)
		if err != ErrNotCached {
			return cachedAddresses, err
		}
	}
	message := dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{question},
	}
	var (
		response *dns.Msg
		err      error
	)
	if responseChecker != nil {
		response, err = c.ExchangeWithResponseCheck(ctx, transport, &message, strategy, func(response *dns.Msg) bool {
			addresses, addrErr := MessageToAddresses(response)
			if addrErr != nil {
				return false
			}
			return responseChecker(addresses)
		})
	} else {
		response, err = c.Exchange(ctx, transport, &message, strategy)
	}
	if err != nil {
		return nil, err
	}
	return MessageToAddresses(response)
}

func (c *Client) questionCache(question dns.Question, transport Transport) ([]netip.Addr, error) {
	response, _ := c.loadResponse(question, transport)
	if response == nil {
		return nil, ErrNotCached
	}
	return MessageToAddresses(response)
}

func (c *Client) loadResponse(question dns.Question, transport Transport) (*dns.Msg, int) {
	var (
		response *dns.Msg
		loaded   bool
	)
	if c.disableExpire {
		if !c.independentCache {
			response, loaded = c.cache.Load(question)
		} else {
			response, loaded = c.transportCache.Load(transportCacheKey{
				Question:      question,
				transportName: transport.Name(),
			})
		}
		if !loaded {
			return nil, 0
		}
		return response.Copy(), 0
	} else {
		var expireAt time.Time
		if !c.independentCache {
			response, expireAt, loaded = c.cache.LoadWithExpire(question)
		} else {
			response, expireAt, loaded = c.transportCache.LoadWithExpire(transportCacheKey{
				Question:      question,
				transportName: transport.Name(),
			})
		}
		if !loaded {
			return nil, 0
		}
		timeNow := time.Now()
		if timeNow.After(expireAt) {
			if !c.independentCache {
				c.cache.Delete(question)
			} else {
				c.transportCache.Delete(transportCacheKey{
					Question:      question,
					transportName: transport.Name(),
				})
			}
			return nil, 0
		}
		var originTTL int
		for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
			for _, record := range recordList {
				if originTTL == 0 || record.Header().Ttl > 0 && int(record.Header().Ttl) < originTTL {
					originTTL = int(record.Header().Ttl)
				}
			}
		}
		nowTTL := int(expireAt.Sub(timeNow).Seconds())
		if nowTTL < 0 {
			nowTTL = 0
		}
		response = response.Copy()
		if originTTL > 0 {
			duration := uint32(originTTL - nowTTL)
			for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					record.Header().Ttl = record.Header().Ttl - duration
				}
			}
		} else {
			for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					record.Header().Ttl = uint32(nowTTL)
				}
			}
		}
		return response, nowTTL
	}
}

func MessageToAddresses(response *dns.Msg) ([]netip.Addr, error) {
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return nil, RCodeError(response.Rcode)
	}
	addresses := make([]netip.Addr, 0, len(response.Answer))
	for _, rawAnswer := range response.Answer {
		switch answer := rawAnswer.(type) {
		case *dns.A:
			addresses = append(addresses, M.AddrFromIP(answer.A))
		case *dns.AAAA:
			addresses = append(addresses, M.AddrFromIP(answer.AAAA))
		case *dns.HTTPS:
			for _, value := range answer.SVCB.Value {
				if value.Key() == dns.SVCB_IPV4HINT || value.Key() == dns.SVCB_IPV6HINT {
					addresses = append(addresses, common.Map(strings.Split(value.String(), ","), M.ParseAddr)...)
				}
			}
		}
	}
	return addresses, nil
}

func wrapError(err error) error {
	switch dnsErr := err.(type) {
	case *net.DNSError:
		if dnsErr.IsNotFound {
			return RCodeNameError
		}
	case *net.AddrError:
		return RCodeNameError
	}
	return err
}
