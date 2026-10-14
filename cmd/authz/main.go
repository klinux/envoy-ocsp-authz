// Command authz é um serviço Envoy ext_authz (gRPC) que valida a revogação, via OCSP,
// do certificado de cliente de uma conexão mTLS. O Envoy valida a cadeia e passa o cert
// no header XFCC; este serviço faz o OCSP (que o Envoy não faz) e, opcionalmente, repassa
// o certificado verificado para o upstream num header configurável.
//
// Config por variáveis de ambiente (ver README):
//
//	LISTEN_ADDR               endereço gRPC do ext_authz (default :9191)
//	METRICS_ADDR              endereço HTTP de /metrics e /healthz (default :9192)
//	ISSUER_CA_FILE            PEM da CA emissora dos certs de cliente (obrigatório)
//	FORWARD_CERT_HEADER       header para repassar o cert verificado ao upstream
//	                          (ex.: ssl-client-cert). Vazio = só allow/deny.
//	OCSP_TIMEOUT              timeout por requisição ao responder (default 5s)
//	OCSP_CACHE_TTL_CAP        teto do cache; nunca além do nextUpdate (default 10m)
//	OCSP_ALLOWED_HOSTS        hosts permitidos do responder, separados por vírgula (anti-SSRF)
//	OCSP_CA_FILE              CA bundle para validar o TLS do responder (default: roots do sistema)
//	OCSP_RESPONDER_URL        se setado, ignora a AIA do cert e usa este responder fixo
//	                          (equivale ao ssl_ocsp_responder do nginx; ex.: o OCSP do Vault ativo)
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/klinux/envoy-ocsp-authz/internal/authz"
	"github.com/klinux/envoy-ocsp-authz/internal/ocsp"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	issuer, err := loadIssuer(env("ISSUER_CA_FILE", ""))
	if err != nil {
		return fmt.Errorf("carregar ISSUER_CA_FILE: %w", err)
	}

	httpClient, err := ocspHTTPClient(env("OCSP_CA_FILE", ""), envDuration("OCSP_TIMEOUT", 5*time.Second))
	if err != nil {
		return err
	}

	verifier := ocsp.New(
		ocsp.WithHTTPClient(httpClient),
		ocsp.WithCacheTTLCap(envDuration("OCSP_CACHE_TTL_CAP", 10*time.Minute)),
		ocsp.WithMaxResponseAge(envDuration("OCSP_MAX_RESPONSE_AGE", 24*time.Hour)),
		ocsp.WithAllowedResponderHosts(csv(env("OCSP_ALLOWED_HOSTS", ""))),
		ocsp.WithResponderURL(env("OCSP_RESPONDER_URL", "")),
	)

	reg := prometheus.NewRegistry()
	srv := authz.NewServer(authz.Config{
		Issuer:     issuer,
		Checker:    verifier,
		Metrics:    authz.NewPromMetrics(reg),
		HeaderName: env("FORWARD_CERT_HEADER", ""),
	})

	// HTTP: métricas + health (readiness do container).
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	metricsAddr := env("METRICS_ADDR", ":9192")
	go func() {
		log.Info("http up", "addr", metricsAddr)
		if err := http.ListenAndServe(metricsAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
		}
	}()

	// gRPC: o serviço ext_authz + health (para o grpc_health_probe do Envoy/k8s).
	grpcAddr := env("LISTEN_ADDR", ":9191")
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return err
	}
	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, srv)
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(gs, hs)

	log.Info("ext_authz up", "addr", grpcAddr, "forwardHeader", env("FORWARD_CERT_HEADER", "(none)"))
	return gs.Serve(lis)
}

func loadIssuer(path string) (*x509.Certificate, error) {
	if path == "" {
		return nil, errors.New("ISSUER_CA_FILE é obrigatório")
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Usa o primeiro certificado do PEM (a CA emissora direta dos certs de cliente).
	certs, err := parseCerts(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse da CA: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("nenhum certificado válido no PEM")
	}
	return certs[0], nil
}

func ocspHTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("carregar OCSP_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("OCSP_CA_FILE sem certificado válido")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		// Não seguir redirects: um responder permitido não pode redirecionar para um
		// host interno e furar o allowlist (anti-SSRF).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func parseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func csv(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
