package ssl

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/osintfw/osint/pkg/types"
)

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func Run(ctx context.Context, target string) types.ModuleResult {
	res := types.ModuleResult{
		Module:    "ssl",
		Target:    target,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	host := target
	if _, _, err := net.SplitHostPort(target); err != nil {
		host = net.JoinHostPort(target, "443")
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		res.Error = err
		return res
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	var certData []map[string]interface{}
	for _, cert := range certs {
		certData = append(certData, map[string]interface{}{
			"subject":    cert.Subject.String(),
			"issuer":     cert.Issuer.String(),
			"not_before": cert.NotBefore,
			"not_after":  cert.NotAfter,
			"dns_names":  cert.DNSNames,
			"sha256":     fmt.Sprintf("%x", sha256.Sum256(cert.Raw)),
			"sha1":       fmt.Sprintf("%x", sha1.Sum(cert.Raw)),
		})
	}

	res.Data["version"] = tlsVersionName(state.Version)
	res.Data["cipher_suite"] = tls.CipherSuiteName(state.CipherSuite)
	res.Data["certificates"] = certData
	res.Data["server_name"] = state.ServerName
	res.Data["handshake_complete"] = state.HandshakeComplete

	return res
}
