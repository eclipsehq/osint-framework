package domain

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
	"github.com/openrdap/rdap"
	"github.com/osintfw/osint/pkg/types"
)

func Run(ctx context.Context, target string) types.ModuleResult {
	res := types.ModuleResult{
		Module:    "domain",
		Target:    target,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	dnsData := make(map[string]interface{})
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	// A
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(target), dns.TypeA)
	if r, _, err := c.ExchangeContext(ctx, msg, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		var recs []string
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				recs = append(recs, a.A.String())
			}
		}
		dnsData["A"] = recs
	}

	// AAAA
	msg.SetQuestion(dns.Fqdn(target), dns.TypeAAAA)
	if r, _, err := c.ExchangeContext(ctx, msg, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		var recs []string
		for _, ans := range r.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok {
				recs = append(recs, aaaa.AAAA.String())
			}
		}
		dnsData["AAAA"] = recs
	}

	// MX
	msg.SetQuestion(dns.Fqdn(target), dns.TypeMX)
	if r, _, err := c.ExchangeContext(ctx, msg, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		var recs []string
		for _, ans := range r.Answer {
			if mx, ok := ans.(*dns.MX); ok {
				recs = append(recs, fmt.Sprintf("%d %s", mx.Preference, mx.Mx))
			}
		}
		dnsData["MX"] = recs
	}

	// TXT
	msg.SetQuestion(dns.Fqdn(target), dns.TypeTXT)
	if r, _, err := c.ExchangeContext(ctx, msg, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		var recs []string
		for _, ans := range r.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				recs = append(recs, strings.Join(txt.Txt, ""))
			}
		}
		dnsData["TXT"] = recs
	}

	// NS
	msg.SetQuestion(dns.Fqdn(target), dns.TypeNS)
	if r, _, err := c.ExchangeContext(ctx, msg, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		var recs []string
		for _, ans := range r.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				recs = append(recs, ns.Ns)
			}
		}
		dnsData["NS"] = recs
	}

	// CAA
	msg.SetQuestion(dns.Fqdn(target), dns.TypeCAA)
	if r, _, err := c.ExchangeContext(ctx, msg, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		var recs []string
		for _, ans := range r.Answer {
			if caa, ok := ans.(*dns.CAA); ok {
				recs = append(recs, fmt.Sprintf("%d %s %s", caa.Flag, caa.Tag, caa.Value))
			}
		}
		dnsData["CAA"] = recs
	}

	// Reverse DNS for first A record
	if aRecs, ok := dnsData["A"].([]string); ok && len(aRecs) > 0 {
		if names, err := net.LookupAddr(aRecs[0]); err == nil {
			dnsData["reverse_dns"] = names
		}
	}

	res.Data["dns"] = dnsData

	// WHOIS
	if raw, err := whois.Whois(target); err == nil {
		if parsed, err := whoisparser.Parse(raw); err == nil {
			res.Data["whois"] = map[string]interface{}{
				"registrar":       parsed.Registrar.Name,
				"creation_date":   parsed.Domain.CreatedDate,
				"expiration_date": parsed.Domain.ExpirationDate,
				"updated_date":    parsed.Domain.UpdatedDate,
				"dnssec":          parsed.Domain.DNSSec,
				"name_servers":    parsed.Domain.NameServers,
				"status":          parsed.Domain.Status,
			}
		} else {
			res.Data["whois_raw"] = raw
		}
	}

	// RDAP
	client := &rdap.Client{}
	req := rdap.NewRequest(rdap.DomainRequest, target)
	if req != nil {
		if resp, err := client.Do(req); err == nil {
			if domain, ok := resp.Object.(*rdap.Domain); ok {
				res.Data["rdap"] = map[string]interface{}{
					"handle":       domain.Handle,
					"ldh_name":     domain.LDHName,
					"object_class": domain.ObjectClassName,
					"entities":     len(domain.Entities),
				}
			}
		}
	}

	return res
}
