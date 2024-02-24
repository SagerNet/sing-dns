package dns

import "github.com/miekg/dns"

func TruncateDNSMessage(request *dns.Msg, response *dns.Msg) (*dns.Msg, int) {
	maxLen := 512
	if edns0Option := request.IsEdns0(); edns0Option != nil {
		if udpSize := int(edns0Option.UDPSize()); udpSize > 0 {
			maxLen = udpSize
		}
	}
	return truncateDNSMessage(response, maxLen)
}

func truncateDNSMessage(response *dns.Msg, maxLen int) (*dns.Msg, int) {
	responseLen := response.Len()
	if responseLen <= maxLen {
		return response, responseLen
	}
	newResponse := *response
	response = &newResponse
	response.Compress = true
	responseLen = response.Len()
	if responseLen <= maxLen {
		return response, responseLen
	}
	for len(response.Answer) > 0 && responseLen > maxLen {
		response.Answer = response.Answer[:len(response.Answer)-1]
		response.Truncated = true
		responseLen = response.Len()
	}
	if responseLen > maxLen {
		response.Ns = nil
		response.Extra = nil
	}
	return response, response.Len()
}
