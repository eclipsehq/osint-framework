package email

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/osintfw/osint/pkg/types"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func Run(ctx context.Context, target string) types.ModuleResult {
	res := types.ModuleResult{
		Module:    "email",
		Target:    target,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	res.Data["valid_syntax"] = emailRegex.MatchString(target)

	parts := strings.Split(target, "@")
	if len(parts) != 2 {
		res.Error = fmt.Errorf("invalid email format")
		return res
	}
	domain := parts[1]

	// MX
	if mxRecords, err := net.LookupMX(domain); err == nil {
		var mxs []string
		for _, mx := range mxRecords {
			mxs = append(mxs, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
		res.Data["mx"] = mxs
	}

	// SPF
	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	if r, _, err := c.ExchangeContext(ctx, msg, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		var spf string
		for _, ans := range r.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				record := strings.Join(txt.Txt, "")
				if strings.HasPrefix(record, "v=spf1") {
					spf = record
				}
			}
		}
		res.Data["spf"] = spf
	}

	// DMARC
	msg.SetQuestion(dns.Fqdn("_dmarc."+domain), dns.TypeTXT)
	if r, _, err := c.ExchangeContext(ctx, msg, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		var dmarc string
		for _, ans := range r.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				record := strings.Join(txt.Txt, "")
				if strings.HasPrefix(record, "v=DMARC1") {
					dmarc = record
				}
			}
		}
		res.Data["dmarc"] = dmarc
	}

	// Gravatar
	hash := fmt.Sprintf("%x", md5.Sum([]byte(strings.ToLower(strings.TrimSpace(target)))))
	res.Data["gravatar_url"] = fmt.Sprintf("https://www.gravatar.com/avatar/%s", hash)

	return res
}
