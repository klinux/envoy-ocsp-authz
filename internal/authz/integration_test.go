//go:build integration

// Teste de integração ponta a ponta contra um Vault PKI real (OCSP de verdade).
// Exercita o produto inteiro: XFCC -> verificação do emissor -> OCSP -> decisão -> header.
//
// Emite certs frescos na hora, então não depende de material pré-gerado. Rodar com:
//
//	VAULT_ADDR=https://vault.stage.cora.local \
//	VAULT_TOKEN="$(cat ~/.vault-stage.token)" \
//	VAULT_PKI=cora_int_direta_pki VAULT_ROLE=cora-integration \
//	go test -tags integration -run TestE2E -v ./internal/authz/
package authz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/klinux/envoy-ocsp-authz/internal/ocsp"
)

type vaultClient struct {
	addr, token, pki, role string
	hc                     *http.Client
}

func vaultFromEnv(t *testing.T) *vaultClient {
	t.Helper()
	v := &vaultClient{
		addr:  os.Getenv("VAULT_ADDR"),
		token: os.Getenv("VAULT_TOKEN"),
		pki:   envOr("VAULT_PKI", "cora_int_direta_pki"),
		role:  envOr("VAULT_ROLE", "cora-integration"),
		// TLS interno do Vault; teste-only.
		hc: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
	}
	if v.addr == "" || v.token == "" {
		t.Skip("VAULT_ADDR/VAULT_TOKEN não definidos; pulando teste de integração")
	}
	return v
}

func envOr(k, def string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return def
}

func (v *vaultClient) do(t *testing.T, method, path, body string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(method, v.addr+"/v1/"+path, strings.NewReader(body))
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := v.hc.Do(req)
	if err != nil {
		t.Fatalf("vault %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("vault %s %s -> %d: %s", method, path, resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// issue devolve o PEM do cert, o serial, e o cert parseado.
func (v *vaultClient) issue(t *testing.T, cn string) (string, string, *x509.Certificate) {
	t.Helper()
	out := v.do(t, "POST", "issue/"+v.role, `{"common_name":"`+cn+`","ttl":"20m"}`)
	data := out["data"].(map[string]any)
	certPEM := data["certificate"].(string)
	serial := data["serial_number"].(string)
	block, _ := pem.Decode([]byte(certPEM))
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, serial, c
}

func (v *vaultClient) revoke(t *testing.T, serial string) {
	t.Helper()
	v.do(t, "POST", "revoke", `{"serial_number":"`+serial+`"}`)
}

func (v *vaultClient) issuerCA(t *testing.T) *x509.Certificate {
	t.Helper()
	req, _ := http.NewRequest("GET", v.addr+"/v1/"+v.pki+"/ca/pem", nil)
	resp, err := v.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	block, _ := pem.Decode(raw)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func xfccHeader(certPEM string) string { return `Cert="` + url.QueryEscape(certPEM) + `"` }

func TestE2E_AgainstRealVault(t *testing.T) {
	v := vaultFromEnv(t)
	issuer := v.issuerCA(t)

	// Verifier apontando pro Vault real, com allowlist do host do responder.
	host := ""
	if u, _ := url.Parse(v.addr); u != nil {
		host = u.Hostname()
	}
	verifier := ocsp.New(
		ocsp.WithHTTPClient(&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}),
		ocsp.WithAllowedResponderHosts([]string{host}),
	)
	srv := NewServer(Config{Issuer: issuer, Checker: verifier, HeaderName: "ssl-client-cert"})

	goodPEM, _, goodCert := v.issue(t, "int-e2egoodzzauditzz0001")
	revPEM, revSerial, _ := v.issue(t, "int-e2erevokezzauditz0001")
	v.revoke(t, revSerial)

	ctx := context.Background()

	// 1) válido -> allow + header com o cert verificado.
	t0 := time.Now()
	resp, _ := srv.Check(ctx, checkReq(xfccHeader(goodPEM)))
	cold := time.Since(t0)
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("válido devia dar OK, veio %d (%s)", resp.GetStatus().GetCode(), resp.GetDeniedResponse().GetBody())
	}
	hdrs := resp.GetOkResponse().GetHeaders()
	if len(hdrs) != 1 || hdrs[0].GetHeader().GetKey() != "ssl-client-cert" {
		t.Fatalf("esperava header ssl-client-cert, veio %v", hdrs)
	}
	// o header decodifica pro mesmo cert.
	dec, _ := url.QueryUnescape(hdrs[0].GetHeader().GetValue())
	if blk, _ := pem.Decode([]byte(dec)); blk == nil {
		t.Fatal("header não decodifica para PEM")
	} else if c, _ := x509.ParseCertificate(blk.Bytes); c == nil || c.SerialNumber.Cmp(goodCert.SerialNumber) != 0 {
		t.Fatal("header não bate com o cert do cliente")
	}

	// 2) segunda chamada -> cache hit (deve ser bem mais rápida que a ida ao responder).
	t1 := time.Now()
	resp2, _ := srv.Check(ctx, checkReq(xfccHeader(goodPEM)))
	warm := time.Since(t1)
	if resp2.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatal("segunda chamada devia dar OK")
	}
	t.Logf("latência cold=%v warm=%v", cold, warm)
	if cold > 6*time.Second {
		t.Fatalf("cold %v estourou o requestTimeout de 6s", cold)
	}
	if warm > cold {
		t.Logf("aviso: warm (%v) não ficou abaixo de cold (%v)", warm, cold)
	}

	// 3) revogado -> 401.
	rresp, _ := srv.Check(ctx, checkReq(xfccHeader(revPEM)))
	assertDenied401(t, rresp)

	// 4) FORWARD_CERT_HEADER vazio -> allow sem header.
	srvNoHdr := NewServer(Config{Issuer: issuer, Checker: verifier, HeaderName: ""})
	nresp, _ := srvNoHdr.Check(ctx, checkReq(xfccHeader(goodPEM)))
	if nresp.GetStatus().GetCode() != int32(codes.OK) || len(nresp.GetOkResponse().GetHeaders()) != 0 {
		t.Fatal("header vazio: esperava allow sem header")
	}

	// 5) responder indisponível (AIA para porta morta) -> fail-closed (401).
	dead := *goodCert
	dead.OCSPServer = []string{"https://127.0.0.1:1/dead"}
	deadVerifier := ocsp.New(ocsp.WithHTTPClient(&http.Client{Timeout: 2 * time.Second}))
	if st, err := deadVerifier.Check(ctx, &dead, issuer); err == nil {
		t.Fatalf("responder morto devia falhar fechado, veio %v", st)
	}
}
