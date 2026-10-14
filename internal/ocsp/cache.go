package ocsp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"
)

// cache guarda o status OCSP por (serial+issuer) até um instante de expiração.
// É limitado por número de entradas; ao encher, descarta as expiradas e, se ainda
// cheio, a entrada que expira mais cedo. Guardar só o status (não a resposta) mantém
// o footprint pequeno e determinístico.
type cache struct {
	mu      sync.Mutex
	max     int
	entries map[string]entry
}

type entry struct {
	status  Status
	expires time.Time
}

func newCache(max int) *cache {
	return &cache{max: max, entries: make(map[string]entry)}
}

func (c *cache) get(key string, now time.Time) (Status, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !now.Before(e.expires) {
		if ok {
			delete(c.entries, key)
		}
		return StatusUnknown, false
	}
	return e.status, true
}

func (c *cache) put(key string, status Status, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.evict()
	}
	c.entries[key] = entry{status: status, expires: expires}
}

// evict remove expiradas; se ainda cheio, remove a que expira mais cedo.
// Chamado com o lock seguro.
func (c *cache) evict() {
	now := time.Now()
	var soonestKey string
	var soonest time.Time
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, k)
			continue
		}
		if soonestKey == "" || e.expires.Before(soonest) {
			soonestKey, soonest = k, e.expires
		}
	}
	if len(c.entries) >= c.max && soonestKey != "" {
		delete(c.entries, soonestKey)
	}
}

// Len devolve o número de entradas (para métricas/testes).
func (c *cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// cacheKey identifica o par (cert, issuer) pelo serial + hash do issuer, de forma estável.
func cacheKey(cert, issuer *x509.Certificate) string {
	h := sha256.New()
	h.Write(issuer.RawSubject)
	h.Write(issuer.RawSubjectPublicKeyInfo)
	h.Write(cert.SerialNumber.Bytes())
	return hex.EncodeToString(h.Sum(nil))
}
