package ocsp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xocsp "golang.org/x/crypto/ocsp"
)

// testPKI é uma CA de teste com um responder OCSP falso assinado pela própria CA.
type testPKI struct {
	caCert   *x509.Certificate
	caKey    *rsa.PrivateKey
	server   *httptest.Server
	status   int       // xocsp.Good / Revoked / Unknown a devolver
	thisUpd  time.Time // janela da resposta
	nextUpd  time.Time
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(der)

	p := &testPKI{caCert: caCert, caKey: caKey, status: xocsp.Good}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		req, err := xocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		this := p.thisUpd
		if this.IsZero() {
			this = time.Now().Add(-time.Minute)
		}
		next := p.nextUpd
		if next.IsZero() {
			next = time.Now().Add(time.Hour)
		}
		tmpl := xocsp.Response{
			Status:       p.status,
			SerialNumber: req.SerialNumber,
			ThisUpdate:   this,
			NextUpdate:   next,
		}
		if p.status == xocsp.Revoked {
			tmpl.RevokedAt = time.Now().Add(-time.Hour)
			tmpl.RevocationReason = xocsp.Unspecified
		}
		resp, err := xocsp.CreateResponse(caCert, caCert, tmpl, caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(p.server.Close)
	return p
}

// leaf emite um certificado de cliente assinado pela CA, com a AIA apontando pro responder.
func (p *testPKI) leaf(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "int-teste"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		OCSPServer:   []string{p.server.URL},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestCheck_Good(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	v := New(WithHTTPClient(p.server.Client()))
	st, err := v.Check(context.Background(), p.leaf(t), p.caCert)
	if err != nil || st != StatusGood {
		t.Fatalf("esperava good, veio %v err=%v", st, err)
	}
}

func TestCheck_Revoked(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Revoked
	v := New(WithHTTPClient(p.server.Client()))
	st, err := v.Check(context.Background(), p.leaf(t), p.caCert)
	if err != nil || st != StatusRevoked {
		t.Fatalf("esperava revoked, veio %v err=%v", st, err)
	}
}

func TestCheck_StaleResponseFailsClosed(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	p.thisUpd = time.Now().Add(-2 * time.Hour)
	p.nextUpd = time.Now().Add(-time.Hour) // já vencida
	v := New(WithHTTPClient(p.server.Client()))
	if _, err := v.Check(context.Background(), p.leaf(t), p.caCert); err == nil {
		t.Fatal("resposta vencida devia falhar fechado")
	}
}

func TestCheck_NoResponder(t *testing.T) {
	p := newTestPKI(t)
	leaf := p.leaf(t)
	leaf.OCSPServer = nil
	v := New(WithHTTPClient(p.server.Client()))
	if _, err := v.Check(context.Background(), leaf, p.caCert); err == nil {
		t.Fatal("sem AIA devia dar erro")
	}
}

func TestCheck_HostAllowlistBlocks(t *testing.T) {
	p := newTestPKI(t)
	v := New(WithHTTPClient(p.server.Client()), WithAllowedResponderHosts([]string{"vault.example.com"}))
	if _, err := v.Check(context.Background(), p.leaf(t), p.caCert); err == nil {
		t.Fatal("responder fora do allowlist devia ser bloqueado")
	}
}

func TestCheck_CacheHitAvoidsSecondCall(t *testing.T) {
	p := newTestPKI(t)
	calls := 0
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; p.server.Config.Handler.ServeHTTP(w, r) })
	ts := httptest.NewServer(wrapped)
	defer ts.Close()
	v := New(WithHTTPClient(ts.Client()))
	leaf := p.leaf(t)
	leaf.OCSPServer = []string{ts.URL}
	for i := 0; i < 3; i++ {
		if _, err := v.Check(context.Background(), leaf, p.caCert); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("esperava 1 chamada ao responder (cache), veio %d", calls)
	}
}

var _ = crypto.SHA1 // evita import não usado se o default mudar
