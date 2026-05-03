package server

import (
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
