// Package authz implementa o serviço Envoy ext_authz (v3) que gating requisições do
// canal matls: extrai o cert do cliente do XFCC, confere que foi emitido pela CA da
// integração direta, checa revogação via OCSP e, se Good, injeta o header ssl-client-cert
// (formato nginx) que o Gravitee e o Keycloak já sabem ler. Qualquer falha nega (401).
package authz

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/klinux/envoy-ocsp-authz/internal/ocsp"
)

// checker é a interface do verificador OCSP (facilita o teste).
type checker interface {
	Check(ctx context.Context, cert, issuer *x509.Certificate) (ocsp.Status, error)
}

// Metrics registra os contadores (implementado em metrics.go; nil-safe).
type Metrics interface {
	Observe(result string, dur time.Duration)
}

// Server implementa authv3.AuthorizationServer.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	issuer     *x509.Certificate
	checker    checker
	metrics    Metrics
	headerName string // header injetado para o upstream (default ssl-client-cert)
	now        func() time.Time
}

// Config configura o Server.
type Config struct {
	Issuer     *x509.Certificate
	Checker    checker
	Metrics    Metrics
	HeaderName string
	Now        func() time.Time
}

// NewServer cria o servidor ext_authz.
func NewServer(c Config) *Server {
	s := &Server{
		issuer:     c.Issuer,
		checker:    c.Checker,
		metrics:    c.Metrics,
		headerName: c.HeaderName,
		now:        c.Now,
	}
	// headerName vazio = allow/deny puro, sem injetar header no upstream.
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Check é o RPC chamado pelo Envoy por requisição.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	start := s.now()
	result, resp := s.decide(ctx, req)
	if s.metrics != nil {
		s.metrics.Observe(result, s.now().Sub(start))
	}
	return resp, nil
}

func (s *Server) decide(ctx context.Context, req *authv3.CheckRequest) (string, *authv3.CheckResponse) {
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	xfcc := headers[XFCCHeader]

	leaf, err := LeafFromXFCC(xfcc)
	if err != nil {
		// Sem cert no XFCC: com mode Optional no listener, chega aqui sem mTLS. Nega.
		return "no_cert", deny()
	}

	// Defesa em profundidade: o leaf tem de ter sido emitido pela CA configurada e estar
	// no período de validade (o Envoy já valida a cadeia, mas confirmamos).
	if err := s.verifyIssuedByCA(leaf); err != nil {
		return "bad_issuer", deny()
	}

	status, err := s.checker.Check(ctx, leaf, s.issuer)
	if err != nil {
		// Fail-closed: erro de OCSP (rede, assinatura, janela, Unknown) nega.
		return "ocsp_error", deny()
	}
	switch status {
	case ocsp.StatusGood:
		if s.headerName == "" {
			return "good", allow("", "") // só allow, sem injetar header
		}
		return "good", allow(s.headerName, encodeCertHeader(leaf))
	case ocsp.StatusRevoked:
		return "revoked", deny()
	default:
		return "unknown", deny()
	}
}

// verifyIssuedByCA confirma assinatura pela CA e validade temporal.
func (s *Server) verifyIssuedByCA(leaf *x509.Certificate) error {
	if s.issuer == nil {
		return errors.New("issuer não configurado")
	}
	if err := leaf.CheckSignatureFrom(s.issuer); err != nil {
		return err
	}
	now := s.now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("certificado fora do período de validade")
	}
	return nil
}

// allow responde OK. Se headerName não for vazio, injeta o header verificado,
// sobrescrevendo qualquer valor que o cliente tenha mandado.
func allow(headerName, headerValue string) *authv3.CheckResponse {
	ok := &authv3.OkHttpResponse{}
	if headerName != "" {
		ok.Headers = []*corev3.HeaderValueOption{{
			Header:       &corev3.HeaderValue{Key: headerName, Value: headerValue},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}}
	}
	return &authv3.CheckResponse{
		Status:       &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: ok},
	}
}

// deny responde 401 JSON {"error":"invalid_client"}, igual ao nginx do matls.
func deny() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Unauthorized},
				Headers: []*corev3.HeaderValueOption{{
					Header: &corev3.HeaderValue{Key: "content-type", Value: "application/json"},
				}},
				Body: `{"error":"invalid_client"}`,
			},
		},
	}
}

// encodeCertHeader produz o PEM percent-encoded como o nginx ($ssl_client_escaped_cert):
// espaço -> %20, nova linha -> %0A. O Gravitee e o Keycloak fazem URLDecode disso.
func encodeCertHeader(cert *x509.Certificate) string {
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	var b strings.Builder
	for _, c := range p {
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			const hexd = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&0x0F])
		}
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
