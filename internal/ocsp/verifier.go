// Package ocsp verifica o status de revogação de um certificado de cliente via OCSP,
// falhando fechado. É o núcleo do ext_authz: dado o certificado do cliente (leaf) e a CA
// emissora, pergunta ao responder OCSP (o do Vault, pela AIA do próprio cert) e devolve
// Good / Revoked / Unknown.
//
// Rigor (validado contra o Vault de stage, mount cora_int_direta_pki):
//   - a assinatura da resposta é conferida contra a CA emissora (ou um responder delegado
//     com EKU id-kp-OCSPSigning), via x/crypto/ocsp.ParseResponseForCert;
//   - a janela thisUpdate/nextUpdate é checada com tolerância de clock;
//   - o nonce é opcional (o Vault não devolve nonce);
//   - qualquer falha (sem AIA, erro de rede, assinatura inválida, resposta fora da janela,
//     status Unknown) resulta em erro -> o ext_authz nega (fail-closed).
package ocsp

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Status é o resultado de uma checagem de revogação.
type Status int

const (
	StatusGood Status = iota
	StatusRevoked
	StatusUnknown
)

func (s Status) String() string {
	switch s {
	case StatusGood:
		return "good"
	case StatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// clockSkew tolera diferença de relógio entre o gateway e o responder.
const clockSkew = 5 * time.Minute

// Verifier faz a checagem OCSP, com cache e um teto para o corpo da resposta.
type Verifier struct {
	httpClient   *http.Client
	cache        *cache
	maxBodyBytes int64
	cacheCap     time.Duration // teto do TTL de cache, independente do nextUpdate
	allowedHosts []string      // se não vazio, só consulta responders nesses hosts (anti-SSRF)
	now          func() time.Time
}

// Option configura o Verifier.
type Option func(*Verifier)

// WithCacheTTLCap limita o TTL de cache (a resposta ainda nunca é cacheada além do nextUpdate).
func WithCacheTTLCap(d time.Duration) Option { return func(v *Verifier) { v.cacheCap = d } }

// WithHTTPClient injeta um http.Client (ex.: com timeout e trust do Vault).
func WithHTTPClient(c *http.Client) Option { return func(v *Verifier) { v.httpClient = c } }

// WithClock injeta o relógio (para testes).
func WithClock(f func() time.Time) Option { return func(v *Verifier) { v.now = f } }

// WithAllowedResponderHosts restringe os responders consultados a esses hosts (match exato
// ou subdomínio). A URL de OCSP vem da AIA do certificado, então, mesmo validando o emissor,
// limitar os hosts evita que uma AIA inesperada vire um vetor de SSRF. Vazio = sem restrição.
func WithAllowedResponderHosts(hosts []string) Option {
	return func(v *Verifier) { v.allowedHosts = hosts }
}

// hostAllowed verifica a URL contra o allowlist (match exato ou subdomínio).
func (v *Verifier) hostAllowed(rawURL string) bool {
	if len(v.allowedHosts) == 0 {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, a := range v.allowedHosts {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// New cria um Verifier.
func New(opts ...Option) *Verifier {
	v := &Verifier{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		cache:        newCache(4096),
		maxBodyBytes: 1 << 20, // 1 MiB; respostas OCSP são pequenas
		cacheCap:     10 * time.Minute,
		now:          time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// ErrNoResponder indica que o certificado não traz URL de OCSP na AIA.
var ErrNoResponder = errors.New("certificado sem endpoint OCSP na AIA")

// Check devolve o status de revogação do cert (leaf) emitido por issuer.
// Retorna erro em qualquer situação em que não se possa afirmar "Good" com segurança.
func (v *Verifier) Check(ctx context.Context, cert, issuer *x509.Certificate) (Status, error) {
	if cert == nil || issuer == nil {
		return StatusUnknown, errors.New("cert ou issuer nulo")
	}
	if hit, ok := v.cache.get(cacheKey(cert, issuer), v.now()); ok {
		return hit, nil
	}

	servers := cert.OCSPServer
	if len(servers) == 0 {
		return StatusUnknown, ErrNoResponder
	}

	reqDER, err := ocsp.CreateRequest(cert, issuer, nil) // nil => CertID com SHA1 (default), o que o responder do Vault aceita
	if err != nil {
		return StatusUnknown, fmt.Errorf("montar OCSP request: %w", err)
	}

	// Tenta cada responder da AIA, em ordem; o primeiro que der resposta conclusiva vence.
	var lastErr error
	for _, url := range servers {
		if !v.hostAllowed(url) {
			lastErr = fmt.Errorf("responder %s fora do allowlist", url)
			continue
		}
		resp, err := v.query(ctx, url, reqDER, cert, issuer)
		if err != nil {
			lastErr = err
			continue
		}
		status, err := interpret(resp, v.now())
		if err != nil {
			lastErr = err
			continue
		}
		v.cache.put(cacheKey(cert, issuer), status, cacheExpiry(resp, v.now(), v.cacheCap))
		return status, nil
	}
	return StatusUnknown, fmt.Errorf("todos os responders OCSP falharam: %w", lastErr)
}

// query faz um POST OCSP e verifica a assinatura da resposta contra o issuer.
func (v *Verifier) query(ctx context.Context, url string, reqDER []byte, cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	httpResp, err := v.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("responder %s devolveu HTTP %d", url, httpResp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, v.maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("ler resposta OCSP: %w", err)
	}

	// ParseResponseForCert confere a assinatura (issuer ou responder delegado com
	// EKU OCSPSigning) e que a resposta cobre ESTE certificado (CertID). O nonce é
	// opcional e não é exigido aqui — o Vault não devolve nonce.
	resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("resposta OCSP inválida de %s: %w", url, err)
	}
	return resp, nil
}

// interpret traduz a resposta OCSP em Status, checando a janela de validade.
func interpret(resp *ocsp.Response, now time.Time) (Status, error) {
	if !resp.ThisUpdate.IsZero() && resp.ThisUpdate.Add(-clockSkew).After(now) {
		return StatusUnknown, errors.New("resposta OCSP ainda não é válida (thisUpdate no futuro)")
	}
	if !resp.NextUpdate.IsZero() && resp.NextUpdate.Add(clockSkew).Before(now) {
		return StatusUnknown, errors.New("resposta OCSP vencida (passou do nextUpdate)")
	}
	switch resp.Status {
	case ocsp.Good:
		return StatusGood, nil
	case ocsp.Revoked:
		return StatusRevoked, nil
	default:
		return StatusUnknown, errors.New("status OCSP Unknown")
	}
}

// cacheExpiry define até quando cachear: nunca além do nextUpdate, nem além do teto.
func cacheExpiry(resp *ocsp.Response, now time.Time, cap time.Duration) time.Time {
	exp := now.Add(cap)
	if !resp.NextUpdate.IsZero() && resp.NextUpdate.Before(exp) {
		exp = resp.NextUpdate
	}
	return exp
}
