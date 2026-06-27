package ip

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/osintfw/osint/internal/config"
	"github.com/osintfw/osint/pkg/types"
)

func Run(ctx context.Context, target string, cfg *config.Config) types.ModuleResult {
	res := types.ModuleResult{
		Module:    "ip",
		Target:    target,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	// Reverse DNS
	if names, err := net.LookupAddr(target); err == nil {
		res.Data["reverse_dns"] = names
	}

	// GeoIP
	if cfg.APIKeys.Ipinfo != "" {
		client := &http.Client{Timeout: 10 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://ipinfo.io/%s/json", target), nil)
		req.Header.Set("Authorization", "Bearer "+cfg.APIKeys.Ipinfo)
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			var geo map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&geo)
			res.Data["geo"] = geo
		}
	} else {
		client := &http.Client{Timeout: 10 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://ip-api.com/json/%s", target), nil)
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			var geo map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&geo)
			res.Data["geo"] = geo
		}
	}

	// ASN via Team Cymru DNS
	reversed := reverseIP(target)
	if reversed != "" {
		asnQuery := reversed + ".origin.asn.cymru.com"
		if txtRecords, err := net.LookupTXT(asnQuery); err == nil && len(txtRecords) > 0 {
			res.Data["asn_txt"] = txtRecords[0]
		}
	}

	return res
}

func reverseIP(ip string) string {
	parts := net.ParseIP(ip).To4()
	if parts == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", parts[3], parts[2], parts[1], parts[0])
}
