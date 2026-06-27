package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/osintfw/osint/pkg/types"
)

func Run(ctx context.Context, target string) types.ModuleResult {
	res := types.ModuleResult{
		Module:    "github",
		Target:    target,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.github.com/users/%s", target), nil)
	req.Header.Set("User-Agent", "OSINT-Framework/1.0")
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		res.Data["found"] = false
		res.Data["status"] = resp.StatusCode
		return res
	}

	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		res.Error = err
		return res
	}

	res.Data["profile"] = user
	res.Data["found"] = true

	// Repos
	reposReq, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.github.com/users/%s/repos?per_page=100", target), nil)
	reposReq.Header.Set("User-Agent", "OSINT-Framework/1.0")
	if reposResp, err := client.Do(reposReq); err == nil {
		defer reposResp.Body.Close()
		if reposResp.StatusCode == 200 {
			var repos []map[string]interface{}
			json.NewDecoder(reposResp.Body).Decode(&repos)
			res.Data["public_repos_count"] = len(repos)
			res.Data["repos"] = repos
		}
	}

	// Orgs
	orgsReq, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.github.com/users/%s/orgs", target), nil)
	orgsReq.Header.Set("User-Agent", "OSINT-Framework/1.0")
	if orgsResp, err := client.Do(orgsReq); err == nil {
		defer orgsResp.Body.Close()
		if orgsResp.StatusCode == 200 {
			var orgs []map[string]interface{}
			json.NewDecoder(orgsResp.Body).Decode(&orgs)
			res.Data["organizations"] = orgs
		}
	}

	return res
}
