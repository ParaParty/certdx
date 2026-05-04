package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/domain"
)

func makeTempCertStore(t *testing.T) CertStore {
	t.Helper()
	dir := t.TempDir()
	return CertStore{
		path:    filepath.Join(dir, "cache.json"),
		entries: make(map[domain.Key]*certStoreEntry),
		update:  make(chan *certStoreEntry, 10),
	}
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
	cs2 := CertStore{
		path:    cs.path,
		entries: make(map[domain.Key]*certStoreEntry),
		update:  make(chan *certStoreEntry, 10),
	}
	if err := cs2.Load(); err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	key := domain.AsKey([]string{"a.com", "b.com"})
	loaded, ok := cs2.entries[key]
	if !ok {
		t.Fatal("entry not found after reload")
	}
	if string(loaded.Cert.FullChain) != "fc" || string(loaded.Cert.Key) != "k" {
		t.Fatalf("cert data mismatch: fc=%q k=%q", loaded.Cert.FullChain, loaded.Cert.Key)
	}
}

func TestCertStoreListenUpdatePersists(t *testing.T) {
	cs := makeTempCertStore(t)
	ctx, cancel := context.WithCancel(context.Background())

	go cs.listenUpdate(ctx)

	cs.update <- &certStoreEntry{
		Domains: []string{"test.com"},
		Cert: CertT{
			FullChain:   []byte("lfc"),
			Key:         []byte("lk"),
			ValidBefore: time.Now().Add(time.Hour),
		},
	}

	// Give the goroutine time to persist.
	time.Sleep(100 * time.Millisecond)
	cancel()
	// Give it time to drain and exit.
	time.Sleep(100 * time.Millisecond)

	// Verify persisted.
	cs2 := CertStore{
		path:    cs.path,
		entries: make(map[domain.Key]*certStoreEntry),
		update:  make(chan *certStoreEntry, 10),
	}
	if err := cs2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	key := domain.AsKey([]string{"test.com"})
	if _, ok := cs2.entries[key]; !ok {
		t.Fatal("entry not persisted by listenUpdate")
	}
}

func TestCertStoreListenUpdateDrainsOnCancel(t *testing.T) {
	cs := makeTempCertStore(t)
	ctx, cancel := context.WithCancel(context.Background())

	// Buffer entries before starting the listener.
	cs.update <- &certStoreEntry{
		Domains: []string{"drain.com"},
		Cert:    CertT{FullChain: []byte("d"), Key: []byte("k"), ValidBefore: time.Now().Add(time.Hour)},
	}

	// Cancel immediately, then start listenUpdate — it should drain
	// the buffered entry before returning.
	cancel()
	cs.listenUpdate(ctx)

	cs2 := CertStore{
		path:    cs.path,
		entries: make(map[domain.Key]*certStoreEntry),
		update:  make(chan *certStoreEntry, 10),
	}
	if err := cs2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	key := domain.AsKey([]string{"drain.com"})
	if _, ok := cs2.entries[key]; !ok {
		t.Fatal("buffered entry not drained on cancel")
	}
}
