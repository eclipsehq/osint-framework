package username

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/osintfw/osint/pkg/types"
)

var sites = map[string]string{
	"GitHub":    "https://github.com/%s",
	"GitLab":    "https://gitlab.com/%s",
	"Twitter":   "https://twitter.com/%s",
	"Reddit":    "https://www.reddit.com/user/%s",
	"Instagram": "https://www.instagram.com/%s",
	"Medium":    "https://medium.com/@%s",
	"Dev.to":    "https://dev.to/%s",
}

func Run(ctx context.Context, target string) types.ModuleResult {
	res := types.ModuleResult{
		Module:    "username",
		Target:    target,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	findings := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for name, urlFmt := range sites {
		wg.Add(1)
		go func(n, u string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, "HEAD", fmt.Sprintf(u, target), nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; OSINT-Framework/1.0)")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			mu.Lock()
			findings[n] = (resp.StatusCode == 200)
			mu.Unlock()
		}(name, urlFmt)
	}

	wg.Wait()
	res.Data["sites"] = findings

	return res
}
