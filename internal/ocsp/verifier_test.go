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
	"sync"
	"sync/atomic"
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
	omitNext bool // se true, devolve resposta SEM nextUpdate
	// Responder delegado opcional: se definido, a resposta é assinada por ele (e embutido).
	respCert *x509.Certificate
	respKey  *rsa.PrivateKey
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
		if next.IsZero() && !p.omitNext {
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
		if p.respCert != nil {
			tmpl.Certificate = p.respCert // embute o responder delegado para o parser verificar
		}
		signerCert, signerKey := caCert, caKey
		if p.respCert != nil {
			signerCert, signerKey = p.respCert, p.respKey
		}
		resp, err := xocsp.CreateResponse(caCert, signerCert, tmpl, signerKey)
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

// Sob carga, N requisições concorrentes para o mesmo cert em cache frio devem coalescer
// numa única consulta ao responder (singleflight), não N chamadas OCSP idênticas.
func TestCheck_ConcurrentColdCacheCoalesced(t *testing.T) {
	p := newTestPKI(t)
	var calls int32
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(50 * time.Millisecond) // segura a flight p/ as goroutines concorrentes empilharem
		p.server.Config.Handler.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(wrapped)
	defer ts.Close()
	v := New(WithHTTPClient(ts.Client()))
	leaf := p.leaf(t)
	leaf.OCSPServer = []string{ts.URL}

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if st, err := v.Check(context.Background(), leaf, p.caCert); err != nil || st != StatusGood {
				t.Errorf("Check concorrente: st=%v err=%v", st, err)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("esperava 1 chamada ao responder (coalescida), veio %d", got)
	}
}

// blockingResponder cria um responder que sinaliza quando o líder entrou na flight (entered)
// e só responde quando release é fechado. Permite exercitar o cancelamento com a flight ativa.
func (p *testPKI) blockingResponder(t *testing.T) (ts *httptest.Server, entered <-chan struct{}, release chan struct{}) {
	t.Helper()
	ent := make(chan struct{}, 1)
	rel := make(chan struct{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case ent <- struct{}{}:
		default:
		}
		<-rel
		p.server.Config.Handler.ServeHTTP(w, r)
	})
	ts = httptest.NewServer(wrapped)
	t.Cleanup(ts.Close)
	return ts, ent, rel
}

// Líder cancelado NÃO pode envenenar um waiter válido: a consulta compartilhada roda num
// contexto desacoplado do líder, então o waiter ainda recebe Good.
func TestCheck_LeaderCancelDoesNotPoisonWaiter(t *testing.T) {
	p := newTestPKI(t)
	ts, entered, release := p.blockingResponder(t)
	v := New(WithHTTPClient(ts.Client()))
	leaf := p.leaf(t)
	leaf.OCSPServer = []string{ts.URL}

	lctx, lcancel := context.WithCancel(context.Background())
	go func() { _, _ = v.Check(lctx, leaf, p.caCert) }() // líder entra na flight
	<-entered

	type res struct {
		st  Status
		err error
	}
	wdone := make(chan res, 1)
	go func() { st, err := v.Check(context.Background(), leaf, p.caCert); wdone <- res{st, err} }()
	time.Sleep(30 * time.Millisecond) // deixa o waiter juntar na flight

	lcancel()      // cancela o LÍDER
	close(release) // libera a consulta compartilhada (independente do ctx do líder)

	select {
	case r := <-wdone:
		if r.err != nil || r.st != StatusGood {
			t.Fatalf("waiter válido deveria receber Good apesar do líder cancelado: st=%v err=%v", r.st, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter não recebeu resultado")
	}
}

// Waiter cancelado desiste da PRÓPRIA espera imediatamente, sem ficar preso até a consulta
// compartilhada (ainda bloqueada) terminar.
func TestCheck_WaiterCancelReturnsPromptly(t *testing.T) {
	p := newTestPKI(t)
	ts, entered, release := p.blockingResponder(t)
	defer close(release) // libera o líder ao final
	v := New(WithHTTPClient(ts.Client()))
	leaf := p.leaf(t)
	leaf.OCSPServer = []string{ts.URL}

	go func() { _, _ = v.Check(context.Background(), leaf, p.caCert) }() // líder preso no handler
	<-entered

	wctx, wcancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := v.Check(wctx, leaf, p.caCert); done <- err }()
	time.Sleep(30 * time.Millisecond) // waiter juntou na flight
	wcancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("waiter cancelado deveria retornar erro de contexto")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("waiter cancelado ficou preso na flight (regressão)")
	}
}

// issueResponder emite um cert assinado pela CA com os EKUs dados (responder delegado),
// válido agora (NotBefore -1min / NotAfter +1h).
func (p *testPKI) issueResponder(t *testing.T, ekus []x509.ExtKeyUsage) (*x509.Certificate, *rsa.PrivateKey) {
	return p.issueResponderValidity(t, ekus, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
}

// issueResponderValidity é como issueResponder mas com a janela de validade explícita.
func (p *testPKI) issueResponderValidity(t *testing.T, ekus []x509.ExtKeyUsage, notBefore, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "responder"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	c, _ := x509.ParseCertificate(der)
	return c, key
}

// Fix 1: um responder delegado SEM id-kp-OCSPSigning (ex.: só ClientAuth) deve ser recusado,
// senão qualquer cert emitido pela CA poderia assinar respostas OCSP.
func TestCheck_DelegatedResponderWithoutOCSPSigningRejected(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	p.respCert, p.respKey = p.issueResponder(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	v := New(WithHTTPClient(p.server.Client()))
	if _, err := v.Check(context.Background(), p.leaf(t), p.caCert); err == nil {
		t.Fatal("responder sem EKU OCSPSigning devia ser recusado")
	}
}

func TestCheck_DelegatedResponderWithOCSPSigningAccepted(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	p.respCert, p.respKey = p.issueResponder(t, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})
	v := New(WithHTTPClient(p.server.Client()))
	st, err := v.Check(context.Background(), p.leaf(t), p.caCert)
	if err != nil || st != StatusGood {
		t.Fatalf("responder delegado válido devia dar good: %v err=%v", st, err)
	}
}

// HIGH: um responder delegado EXPIRADO deve ser recusado (fail-closed). Senão, quem
// tivesse a chave antiga do responder e controlasse/interceptasse o endpoint poderia
// forjar "Good" para um certificado revogado.
func TestCheck_DelegatedResponderExpiredRejected(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	p.respCert, p.respKey = p.issueResponderValidity(t,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	v := New(WithHTTPClient(p.server.Client()))
	if _, err := v.Check(context.Background(), p.leaf(t), p.caCert); err == nil {
		t.Fatal("responder delegado expirado devia ser recusado")
	}
}

// Simétrico: responder delegado ainda-não-válido (NotBefore no futuro) também é recusado.
func TestCheck_DelegatedResponderNotYetValidRejected(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	p.respCert, p.respKey = p.issueResponderValidity(t,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	v := New(WithHTTPClient(p.server.Client()))
	if _, err := v.Check(context.Background(), p.leaf(t), p.caCert); err == nil {
		t.Fatal("responder delegado ainda-não-válido devia ser recusado")
	}
}

// Fix 2: resposta Good antiga SEM nextUpdate não pode valer para sempre.
func TestCheck_NoNextUpdateStaleRejected(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	p.thisUpd = time.Now().Add(-48 * time.Hour)
	p.omitNext = true // sem nextUpdate
	v := New(WithHTTPClient(p.server.Client()), WithMaxResponseAge(24*time.Hour))
	if _, err := v.Check(context.Background(), p.leaf(t), p.caCert); err == nil {
		t.Fatal("resposta velha sem nextUpdate devia ser recusada")
	}
}

func TestCheck_NoNextUpdateFreshAccepted(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	p.thisUpd = time.Now().Add(-time.Minute)
	p.omitNext = true
	v := New(WithHTTPClient(p.server.Client()), WithMaxResponseAge(24*time.Hour))
	if st, err := v.Check(context.Background(), p.leaf(t), p.caCert); err != nil || st != StatusGood {
		t.Fatalf("resposta recente sem nextUpdate devia dar good: %v err=%v", st, err)
	}
}

// Fix 6: o client default não segue redirects (um responder permitido não pode
// redirecionar para um host interno).
func TestCheck_RedirectNotFollowed(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p.server.URL, http.StatusFound)
	}))
	defer redir.Close()
	leaf := p.leaf(t)
	leaf.OCSPServer = []string{redir.URL}
	v := New() // client default (noRedirectClient)
	if _, err := v.Check(context.Background(), leaf, p.caCert); err == nil {
		t.Fatal("redirect do responder não devia ser seguido")
	}
}

// WithResponderURL deve ignorar a AIA do cert (inclusive quando ausente) e furar o allowlist,
// espelhando o ssl_ocsp_responder do nginx (responder fixo, ex.: Vault ativo).
func TestCheck_ResponderURLOverridesAIA(t *testing.T) {
	p := newTestPKI(t)
	p.status = xocsp.Good
	leaf := p.leaf(t)
	leaf.OCSPServer = nil // cert sem AIA

	// sem override: sem AIA => falha fechado.
	if _, err := New(WithHTTPClient(p.server.Client())).Check(context.Background(), leaf, p.caCert); err == nil {
		t.Fatal("sem AIA e sem override devia falhar")
	}

	// com override: usa o endpoint fixo e dá Good, mesmo sem AIA e com allowlist restrito a outro host.
	v := New(
		WithHTTPClient(p.server.Client()),
		WithResponderURL(p.server.URL),
		WithAllowedResponderHosts([]string{"nada.example.com"}),
	)
	st, err := v.Check(context.Background(), leaf, p.caCert)
	if err != nil || st != StatusGood {
		t.Fatalf("override devia dar good ignorando AIA/allowlist: %v err=%v", st, err)
	}
}

var _ = crypto.SHA1 // evita import não usado se o default mudar
