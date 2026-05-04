package server

import (
	"context"
	"sync"
	"testing"
	"time"
)

func makeValidTestEntry() *certEntry {
	entry := newCertEntry([]string{"example.com"})
	entry.cert = CertT{ValidBefore: time.Now().Add(time.Hour)}
	return entry
}

func TestSubscribeReleaseClearsRenewer(t *testing.T) {
	s := MakeCertDXServer()
	entry := makeValidTestEntry()

	s.subscribe(entry)

	entry.stateMu.Lock()
	if entry.subscribing != 1 {
		t.Fatalf("subscribing = %d, want 1", entry.subscribing)
	}
	if entry.cancelRenew == nil {
		t.Fatal("cancelRenew is nil after first subscribe")
	}
	entry.stateMu.Unlock()

	s.release(entry)

	entry.stateMu.Lock()
	defer entry.stateMu.Unlock()
	if entry.subscribing != 0 {
		t.Fatalf("subscribing = %d, want 0", entry.subscribing)
	}
	if entry.cancelRenew != nil {
		t.Fatal("cancelRenew was not cleared after last release")
	}
}

func TestSubscribeReleaseConcurrentBalanced(t *testing.T) {
	s := MakeCertDXServer()
	entry := makeValidTestEntry()

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.subscribe(entry)
			s.release(entry)
		}()
	}
	wg.Wait()

	entry.stateMu.Lock()
	defer entry.stateMu.Unlock()
	if entry.subscribing != 0 {
		t.Fatalf("subscribing = %d, want 0", entry.subscribing)
	}
	if entry.cancelRenew != nil {
		t.Fatal("cancelRenew was not cleared after balanced releases")
	}
}

func TestNewCertEntryInitialization(t *testing.T) {
	entry := newCertEntry([]string{"a.com", "b.com"})
	if len(entry.domains) != 2 || entry.domains[0] != "a.com" {
		t.Fatalf("domains: got %v", entry.domains)
	}
	if entry.version != 0 {
		t.Fatalf("version: got %d want 0", entry.version)
	}
	if entry.updated == nil {
		t.Fatal("updated channel is nil")
	}
	if entry.subscribing != 0 {
		t.Fatalf("subscribing: got %d want 0", entry.subscribing)
	}
	// Zero-value CertT should not be valid.
	if entry.cert.IsValid() {
		t.Fatal("zero-value cert should not be valid")
	}
}

func TestCertTIsValid(t *testing.T) {
	cases := []struct {
		name  string
		cert  CertT
		valid bool
	}{
		{"future", CertT{ValidBefore: time.Now().Add(time.Hour)}, true},
		{"past", CertT{ValidBefore: time.Now().Add(-time.Hour)}, false},
		{"zero", CertT{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cert.IsValid(); got != tc.valid {
				t.Fatalf("IsValid = %v, want %v", got, tc.valid)
			}
		})
	}
}

func TestSnapshotReturnsCurrentState(t *testing.T) {
	entry := newCertEntry([]string{"example.com"})
	entry.cert = CertT{FullChain: []byte("fc"), Key: []byte("k"), ValidBefore: time.Now().Add(time.Hour)}
	entry.version = 42

	cert, ver := entry.Snapshot()
	if ver != 42 {
		t.Fatalf("version: got %d want 42", ver)
	}
	if string(cert.FullChain) != "fc" {
		t.Fatalf("fullchain: got %q", cert.FullChain)
	}
	if string(cert.Key) != "k" {
		t.Fatalf("key: got %q", cert.Key)
	}
}

func TestCertReturnsFullChain(t *testing.T) {
	entry := newCertEntry([]string{"example.com"})
	entry.cert = CertT{FullChain: []byte("chain"), ValidBefore: time.Now().Add(time.Hour)}

	cert := entry.Cert()
	if string(cert.FullChain) != "chain" {
		t.Fatalf("Cert().FullChain: got %q", cert.FullChain)
	}
}

func TestWaitForUpdateReturnsImmediatelyIfVersionAdvanced(t *testing.T) {
	entry := newCertEntry([]string{"example.com"})
	entry.version = 5

	got := entry.WaitForUpdate(context.Background(), 3)
	if got != 5 {
		t.Fatalf("WaitForUpdate: got %d want 5", got)
	}
}

func TestWaitForUpdateBlocksUntilUpdate(t *testing.T) {
	entry := newCertEntry([]string{"example.com"})
	entry.version = 1

	done := make(chan uint64, 1)
	go func() {
		done <- entry.WaitForUpdate(context.Background(), 1)
	}()

	// Simulate an update.
	time.Sleep(50 * time.Millisecond)
	entry.stateMu.Lock()
	entry.version = 2
	close(entry.updated)
	entry.updated = make(chan struct{})
	entry.stateMu.Unlock()

	select {
	case v := <-done:
		if v != 2 {
			t.Fatalf("WaitForUpdate: got %d want 2", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForUpdate did not return after update")
	}
}

func TestWaitForUpdateRespectsContextCancel(t *testing.T) {
	entry := newCertEntry([]string{"example.com"})
	entry.version = 1

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan uint64, 1)
	go func() {
		done <- entry.WaitForUpdate(ctx, 1)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case v := <-done:
		// Version unchanged since no update happened.
		if v != 1 {
			t.Fatalf("WaitForUpdate: got %d want 1", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForUpdate did not return after ctx cancel")
	}
}

func TestCertCacheGetCreatesAndDeduplicates(t *testing.T) {
	cc := makeCertCache()

	e1 := cc.get([]string{"a.com"})
	e2 := cc.get([]string{"a.com"})
	if e1 != e2 {
		t.Fatal("get returned different entries for the same domains")
	}

	e3 := cc.get([]string{"b.com"})
	if e1 == e3 {
		t.Fatal("get returned the same entry for different domains")
	}
}

func TestIsSubscribingReflectsState(t *testing.T) {
	s := MakeCertDXServer()
	entry := makeValidTestEntry()

	if s.isSubscribing(entry) {
		t.Fatal("fresh entry should not be subscribing")
	}

	s.subscribe(entry)
	if !s.isSubscribing(entry) {
		t.Fatal("entry should be subscribing after subscribe")
	}

	s.release(entry)
	// Give the renew goroutine a moment to wind down.
	time.Sleep(50 * time.Millisecond)
	if s.isSubscribing(entry) {
		t.Fatal("entry should not be subscribing after release")
	}
}
