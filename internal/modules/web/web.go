package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/osintfw/osint/pkg/types"
	"golang.org/x/net/html"
)

type capTransport struct {
	base http.RoundTripper
	caps []capturedResponse
}

type capturedResponse struct {
	URL        string
	StatusCode int
	Headers    http.Header
}

func (t *capTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	t.caps = append(t.caps, capturedResponse{
		URL:        req.URL.String(),
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
	})
	return resp, nil
}

func Run(ctx context.Context, target string) types.ModuleResult {
	res := types.ModuleResult{
		Module:    "web",
		Target:    target,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	u, err := url.Parse(target)
	if err != nil {
		res.Error = err
		return res
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	cap := &capTransport{base: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	client := &http.Client{
		Transport: cap,
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		res.Error = err
		return res
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; OSINT-Framework/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	sbody := string(body)

	title := extractTitle(sbody)
	server := resp.Header.Get("Server")

	secHeaders := map[string]string{
		"Strict-Transport-Security": resp.Header.Get("Strict-Transport-Security"),
		"Content-Security-Policy":   resp.Header.Get("Content-Security-Policy"),
		"X-Frame-Options":           resp.Header.Get("X-Frame-Options"),
		"X-Content-Type-Options":    resp.Header.Get("X-Content-Type-Options"),
		"Referrer-Policy":           resp.Header.Get("Referrer-Policy"),
		"Permissions-Policy":        resp.Header.Get("Permissions-Policy"),
	}

	var redirects []map[string]interface{}
	for _, c := range cap.caps {
		redirects = append(redirects, map[string]interface{}{
			"url":         c.URL,
			"status_code": c.StatusCode,
		})
	}

	techs := detectTech(resp.Header, sbody)
	og := extractMeta(sbody, "og:")

	res.Data["title"] = title
	res.Data["server"] = server
	res.Data["status_code"] = resp.StatusCode
	res.Data["headers"] = resp.Header
	res.Data["security_headers"] = secHeaders
	res.Data["redirect_chain"] = redirects
	res.Data["technologies"] = techs
	res.Data["open_graph"] = og
	res.Data["content_length"] = len(body)

	// robots.txt
	robotsURL := u.Scheme + "://" + u.Host + "/robots.txt"
	rReq, _ := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if rResp, err := client.Do(rReq); err == nil {
		if rResp.StatusCode == 200 {
			rb, _ := io.ReadAll(rResp.Body)
			res.Data["robots_txt"] = string(rb)
		}
		rResp.Body.Close()
	}

	// sitemap.xml
	sitemapURL := u.Scheme + "://" + u.Host + "/sitemap.xml"
	sReq, _ := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
	if sResp, err := client.Do(sReq); err == nil {
		if sResp.StatusCode == 200 {
			sb, _ := io.ReadAll(sResp.Body)
			res.Data["sitemap_xml"] = string(sb)
		}
		sResp.Body.Close()
	}

	// Cookies
	var cookies []map[string]string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, map[string]string{
			"name":     c.Name,
			"value":    c.Value,
			"domain":   c.Domain,
			"path":     c.Path,
			"secure":   fmt.Sprintf("%v", c.Secure),
			"httponly": fmt.Sprintf("%v", c.HttpOnly),
		})
	}
	res.Data["cookies"] = cookies

	return res
}

func extractTitle(body string) string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return ""
	}
	var title string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
			title = n.FirstChild.Data
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return strings.TrimSpace(title)
}

func extractMeta(body, prefix string) map[string]string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	meta := make(map[string]string)
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			var name, content string
			for _, a := range n.Attr {
				if a.Key == "name" || a.Key == "property" {
					name = a.Val
				}
				if a.Key == "content" {
					content = a.Val
				}
			}
			if strings.HasPrefix(name, prefix) {
				meta[name] = content
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return meta
}

func detectTech(headers http.Header, body string) []string {
	var techs []string
	srv := headers.Get("Server")
	pwr := headers.Get("X-Powered-By")

	if strings.Contains(srv, "nginx") {
		techs = append(techs, "nginx")
	} else if strings.Contains(srv, "Apache") {
		techs = append(techs, "Apache")
	} else if strings.Contains(srv, "cloudflare") {
		techs = append(techs, "Cloudflare")
	} else if strings.Contains(srv, "Microsoft-IIS") {
		techs = append(techs, "IIS")
	}

	if strings.Contains(pwr, "PHP") {
		techs = append(techs, "PHP")
	} else if strings.Contains(pwr, "ASP.NET") {
		techs = append(techs, "ASP.NET")
	}

	if strings.Contains(body, "wp-content") {
		techs = append(techs, "WordPress")
	}
	if strings.Contains(body, "drupal") {
		techs = append(techs, "Drupal")
	}
	if strings.Contains(body, "react") {
		techs = append(techs, "React")
	}
	if strings.Contains(body, "vue") {
		techs = append(techs, "Vue.js")
	}
	if strings.Contains(body, "angular") {
		techs = append(techs, "Angular")
	}

	return techs
}
