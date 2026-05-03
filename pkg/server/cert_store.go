package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/paths"
)

type certStoreEntry struct {
	Domains []string `json:"domains"`
	Cert    CertT    `json:"cert"`
}

// CertStore handles persistent storage of obtained certificates as the
// server's cache.json file.
type CertStore struct {
	path    string
	entries map[domain.Key]*certStoreEntry
	update  chan *certStoreEntry
}

// NewCertStore constructs a CertStore backed by the default cache.json path.
func NewCertStore() CertStore {
	return CertStore{
		path:    paths.ServerCacheSave(),
		entries: make(map[domain.Key]*certStoreEntry),
		update:  make(chan *certStoreEntry, 10),
	}
}

// Load reads and unmarshals the persisted certificate store. It returns
// os.ErrNotExist when the backing file hasn't been created yet.
func (s *CertStore) Load() error {
	if !paths.FileExists(s.path) {
		return os.ErrNotExist
	}

	cfile, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("opening cert store: %w", err)
	}

	if err := json.Unmarshal(cfile, &s.entries); err != nil {
		return fmt.Errorf("unmarshaling cert store: %w", err)
	}

	return nil
}

func (s *CertStore) save() error {
	jsonBytes, err := json.Marshal(s.entries)
	if err != nil {
		return fmt.Errorf("marshal cert store: %w", err)
	}

	if err := os.WriteFile(s.path, jsonBytes, 0o600); err != nil {
		return fmt.Errorf("write cert store: %w", err)
	}

	return nil
}

func (s *CertStore) saveEntry(fe *certStoreEntry) error {
	s.entries[domain.AsKey(fe.Domains)] = fe
	return s.save()
}

func (s *CertStore) PrintCertInfo() {
	for _, cert := range s.entries {
		fmt.Printf("\nDomains:     %s\nRenewAt:     %s\nValidBefore: %s\n", strings.Join(cert.Domains, ", "), cert.Cert.RenewAt, cert.Cert.ValidBefore)
	}
}

// listenUpdate drains the cert-store update queue, persisting each renewed cert
// to disk. When ctx is done, it flushes queued updates before exiting so a
// renewal that completed just before shutdown is not dropped.
func (s *CertStore) listenUpdate(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case fe := <-s.update:
					s.logSaveEntry(fe)
				default:
					return
				}
			}
		case fe := <-s.update:
			s.logSaveEntry(fe)
		}
	}
}

func (s *CertStore) logSaveEntry(fe *certStoreEntry) {
	logging.Info("Update domains cache to file")
	if err := s.saveEntry(fe); err != nil {
		logging.Warn("Update domains cache to file failed, err: %s", err)
	}
}
