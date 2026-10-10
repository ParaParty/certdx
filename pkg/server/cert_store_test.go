package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/domain"
)

func makeTempCertStore(t *testing.T) *CertStore {
	t.Helper()
	return &CertStore{
		path:    filepath.Join(t.TempDir(), "cache.json"),
		entries: make(map[domain.Key]*certStoreEntry),
	}
}

// reloadCertStore reads back what is on disk at cs.path.
func reloadCertStore(t *testing.T, cs *CertStore) *CertStore {
	t.Helper()
	cs2 := &CertStore{path: cs.path, entries: make(map[domain.Key]*certStoreEntry)}
	if err := cs2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cs2
}

func TestCertStoreLoadMissingFile(t *testing.T) {
	cs := makeTempCertStore(t)
	err := cs.Load()
	if !os.IsNotExist(err) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestCertStoreLoadCorruptedJSON(t *testing.T) {
	cs := makeTempCertStore(t)
	if err := os.WriteFile(cs.path, []byte("{invalid json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := cs.Load()
	if err == nil {
		t.Fatal("expected error on corrupted JSON")
	}
}

func TestCertStoreLoadValid(t *testing.T) {
	cs := makeTempCertStore(t)

	entry := &certStoreEntry{
		Domains: []string{"example.com"},
		Cert: CertT{
			FullChain:   []byte("chain"),
			Key:         []byte("key"),
			ValidBefore: time.Now().Add(time.Hour),
		},
	}
	data := map[domain.Key]*certStoreEntry{
		domain.AsKey(entry.Domains): entry,
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(cs.path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := cs.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	key := domain.AsKey([]string{"example.com"})
	loaded, ok := cs.entries[key]
	if !ok {
		t.Fatal("entry not found after load")
	}
	if string(loaded.Cert.FullChain) != "chain" {
		t.Fatalf("fullchain: got %q", loaded.Cert.FullChain)
	}
}

func TestCertStoreLoadSkipsNullEntries(t *testing.T) {
	cs := makeTempCertStore(t)

	valid := CertT{FullChain: []byte("fc"), Key: []byte("k"), ValidBefore: time.Now().Add(time.Hour)}
	raw := map[string]*certStoreEntry{
		"1": {Domains: []string{"example.com"}, Cert: valid},
		"2": nil,
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(cs.path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := cs.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cs.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(cs.entries))
	}
}

func TestCertStoreLoadCanonicalizesLegacyEntries(t *testing.T) {
	cs := makeTempCertStore(t)

	valid := CertT{FullChain: []byte("fc"), Key: []byte("k"), ValidBefore: time.Now().Add(time.Hour)}
	raw := map[string]*certStoreEntry{
		"1": {Domains: []string{"www.example.com", "Example.com."}, Cert: valid},
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(cs.path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := cs.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"example.com", "www.example.com"}
	loaded, ok := cs.entries[domain.AsKey(want)]
	if !ok {
		t.Fatal("legacy entry not keyed by its canonical domain set")
	}
	if !slices.Equal(loaded.Domains, want) {
		t.Fatalf("domains: got %q want %q", loaded.Domains, want)
	}
}

func TestCertStoreSaveAndLoad(t *testing.T) {
	cs := makeTempCertStore(t)

	entry := &certStoreEntry{
		Domains: []string{"a.com", "b.com"},
		Cert: CertT{
			FullChain:   []byte("fc"),
			Key:         []byte("k"),
			ValidBefore: time.Now().Add(2 * time.Hour),
			RenewAt:     time.Now(),
		},
	}
	if err := cs.saveEntry(entry); err != nil {
		t.Fatalf("saveEntry: %v", err)
	}

	// Check file permissions.
	st, err := os.Stat(cs.path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("perm: got %o want 0600", mode)
	}

	// Reload into a fresh store.
	cs2 := reloadCertStore(t, cs)
	key := domain.AsKey([]string{"a.com", "b.com"})
	loaded, ok := cs2.entries[key]
	if !ok {
		t.Fatal("entry not found after reload")
	}
	if string(loaded.Cert.FullChain) != "fc" || string(loaded.Cert.Key) != "k" {
		t.Fatalf("cert data mismatch: fc=%q k=%q", loaded.Cert.FullChain, loaded.Cert.Key)
	}
}

func TestCertStoreConcurrentSaves(t *testing.T) {
	cs := makeTempCertStore(t)

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			err := cs.saveEntry(&certStoreEntry{
				Domains: []string{fmt.Sprintf("d%d.example.com", i)},
				Cert:    CertT{FullChain: []byte("fc"), Key: []byte("k"), ValidBefore: time.Now().Add(time.Hour)},
			})
			if err != nil {
				t.Errorf("saveEntry: %v", err)
			}
		})
	}
	wg.Wait()

	if n := len(reloadCertStore(t, cs).entries); n != 10 {
		t.Fatalf("persisted %d entries, want 10", n)
	}
}

func TestRenewPersistsCert(t *testing.T) {
	s := makeTestServer("", "/", []string{"example.com"})
	s.certStore = makeTempCertStore(t)
	s.acme = acme.NewMockACME(48 * time.Hour)

	entry := newCertEntry([]string{"example.com"})
	if obtained, err := s.renew(context.Background(), entry, false); err != nil || !obtained {
		t.Fatalf("renew: obtained=%v err=%v", obtained, err)
	}

	if _, ok := reloadCertStore(t, s.certStore).entries[domain.AsKey([]string{"example.com"})]; !ok {
		t.Fatal("obtained cert was not persisted")
	}
}
