package aliesa

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	esa "github.com/alibabacloud-go/esa-20240910/v2/client"
	"github.com/alibabacloud-go/tea/dara"

	"pkg.para.party/certdx/pkg/config"
)

type fakeESA struct {
	entries     []*esa.ListCertificatesResponseBodyResult
	certs       map[string]string
	status      string
	outerStatus bool
	sets        []*esa.SetCertificateRequest
	deletes     []string
	events      []string
	setErr      error
	deleteErr   error
}

func (f *fakeESA) ListCertificatesWithContext(ctx context.Context, req *esa.ListCertificatesRequest, _ *dara.RuntimeOptions) (*esa.ListCertificatesResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &esa.ListCertificatesResponse{Body: &esa.ListCertificatesResponseBody{Result: f.entries}}, nil
}

func (f *fakeESA) GetCertificateWithContext(ctx context.Context, req *esa.GetCertificateRequest, _ *dara.RuntimeOptions) (*esa.GetCertificateResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	certPEM := f.certs[*req.Id]
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return &esa.GetCertificateResponse{Body: &esa.GetCertificateResponseBody{}}, nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	body := &esa.GetCertificateResponseBody{
		Certificate: &certPEM,
		Result: &esa.GetCertificateResponseBodyResult{
			FingerprintSha256: ptr(fingerprint(leaf)),
		},
	}
	if f.outerStatus {
		body.Status = ptr(f.status)
	} else {
		body.Result.Status = ptr(f.status)
	}
	return &esa.GetCertificateResponse{Body: body}, nil
}

func (f *fakeESA) SetCertificateWithContext(ctx context.Context, req *esa.SetCertificateRequest, _ *dara.RuntimeOptions) (*esa.SetCertificateResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.setErr != nil {
		return nil, f.setErr
	}
	if len(f.entries) >= uploadQuota {
		return nil, fmt.Errorf("upload quota exceeded")
	}
	f.sets = append(f.sets, req)
	f.events = append(f.events, "set")
	id := fmt.Sprintf("new-cert-%d", len(f.sets))
	leaf, err := parseLeaf([]byte(*req.Certificate))
	if err != nil {
		return nil, err
	}
	f.certs[id] = *req.Certificate
	entry := testEntry(id, leaf)
	entry.Name = req.Name
	entry.CreateTime = ptr(time.Now().UTC().Format("2006-01-02 15:04:05"))
	f.entries = append(f.entries, entry)
	return &esa.SetCertificateResponse{Body: &esa.SetCertificateResponseBody{Id: &id}}, nil
}

func (f *fakeESA) DeleteCertificateWithContext(ctx context.Context, req *esa.DeleteCertificateRequest, _ *dara.RuntimeOptions) (*esa.DeleteCertificateResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	f.deletes = append(f.deletes, *req.Id)
	f.events = append(f.events, "delete:"+*req.Id)
	for i, entry := range f.entries {
		if stringValue(entry.Id) == *req.Id {
			f.entries = append(f.entries[:i], f.entries[i+1:]...)
			break
		}
	}
	delete(f.certs, *req.Id)
	return &esa.DeleteCertificateResponse{Body: &esa.DeleteCertificateResponseBody{Id: req.Id}}, nil
}

func ptr(s string) *string { return &s }

func testMaterial(t *testing.T, expires time.Time) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(expires.Unix()),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "*.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     expires,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), leaf
}

func testEntry(id string, leaf *x509.Certificate) *esa.ListCertificatesResponseBodyResult {
	return &esa.ListCertificatesResponseBodyResult{
		Id:                ptr(id),
		Type:              ptr("upload"),
		SAN:               ptr(strings.Join(leaf.DNSNames, ",")),
		FingerprintSha256: ptr(fingerprint(leaf)),
	}
}

func testAction(api *fakeESA) *Action {
	return &Action{cfg: &config.AliESAAction{SiteID: 123}, client: api}
}

func testCertificate() *config.ClientCertificate {
	return &config.ClientCertificate{Name: "web", Domains: []string{"*.example.com", "example.com"}}
}

func TestNewUsesRegionalEndpoint(t *testing.T) {
	action, err := New(&config.AliESAAction{SiteID: 123}, &config.AliESAProfile{
		AccessKeyID: "id", AccessKeySecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	api := action.client.(*esa.Client)
	if got := stringValue(api.Endpoint); got != "esa.cn-hangzhou.aliyuncs.com" {
		t.Fatalf("endpoint = %q, want Hangzhou public endpoint", got)
	}
	if got := stringValue(api.RegionId); got != defaultRegionID {
		t.Fatalf("region = %q, want %q", got, defaultRegionID)
	}
}

func TestNewUsesConfiguredEndpointAndRegion(t *testing.T) {
	action, err := New(&config.AliESAAction{SiteID: 123}, &config.AliESAProfile{
		AccessKeyID: "id", AccessKeySecret: "secret",
		RegionID: "ap-southeast-1", Endpoint: "esa-vpc.ap-southeast-1.aliyuncs.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	api := action.client.(*esa.Client)
	if got := stringValue(api.Endpoint); got != "esa-vpc.ap-southeast-1.aliyuncs.com" {
		t.Fatalf("endpoint = %q, want configured VPC endpoint", got)
	}
	if got := stringValue(api.RegionId); got != "ap-southeast-1" {
		t.Fatalf("region = %q, want ap-southeast-1", got)
	}
}

func TestNewDerivesEndpointFromRegion(t *testing.T) {
	action, err := New(&config.AliESAAction{SiteID: 123}, &config.AliESAProfile{
		AccessKeyID: "id", AccessKeySecret: "secret", RegionID: "ap-southeast-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	api := action.client.(*esa.Client)
	if got := stringValue(api.Endpoint); got != "esa.ap-southeast-1.aliyuncs.com" {
		t.Fatalf("endpoint = %q, want Singapore public endpoint", got)
	}
}

func TestUploadNewCertificate(t *testing.T) {
	fullchain, key, leaf := testMaterial(t, time.Now().Add(48*time.Hour))
	api := &fakeESA{certs: map[string]string{}, status: "OK"}
	if err := testAction(api).Update(context.Background(), fullchain, key, testCertificate()); err != nil {
		t.Fatal(err)
	}
	if len(api.sets) != 1 || api.sets[0].Id != nil || *api.sets[0].SiteId != 123 ||
		*api.sets[0].Type != "upload" || *api.sets[0].Name != "certdx-123-"+fingerprint(leaf)[:12] {
		t.Fatalf("unexpected SetCertificate request: %+v", api.sets)
	}
}

func TestCloudCertificateIsLeftAlone(t *testing.T) {
	cloudPEM, _, cloudLeaf := testMaterial(t, time.Now().Add(24*time.Hour))
	fullchain, key, _ := testMaterial(t, time.Now().Add(48*time.Hour))
	cloud := testEntry("cloud-cert", cloudLeaf)
	cloud.Type = ptr("cas")
	api := &fakeESA{
		entries: []*esa.ListCertificatesResponseBodyResult{cloud},
		certs:   map[string]string{"cloud-cert": string(cloudPEM)},
		status:  "OK",
	}
	if err := testAction(api).Update(context.Background(), fullchain, key, testCertificate()); err != nil {
		t.Fatal(err)
	}
	if len(api.sets) != 1 || api.sets[0].Id != nil || api.certs["cloud-cert"] != string(cloudPEM) {
		t.Fatalf("cloud certificate should remain intact; requests: %+v", api.sets)
	}
}

func TestUploadNewVersionWithoutOverwritingOld(t *testing.T) {
	oldPEM, _, oldLeaf := testMaterial(t, time.Now().Add(24*time.Hour))
	fullchain, key, _ := testMaterial(t, time.Now().Add(48*time.Hour))
	old := testEntry("old-cert", oldLeaf)
	old.Name = ptr("certdx-123-web-old")
	old.CreateTime = ptr("2026-01-01 00:00:00")
	api := &fakeESA{
		entries: []*esa.ListCertificatesResponseBodyResult{old},
		certs:   map[string]string{"old-cert": string(oldPEM)},
		status:  "OK",
	}
	if err := testAction(api).Update(context.Background(), fullchain, key, testCertificate()); err != nil {
		t.Fatal(err)
	}
	if len(api.sets) != 1 || api.sets[0].Id != nil || api.certs["old-cert"] != string(oldPEM) {
		t.Fatalf("expected a new certificate while preserving the old one, got %+v", api.sets)
	}
}

func TestAlreadyStoredCertificateSkipsUpload(t *testing.T) {
	fullchain, key, leaf := testMaterial(t, time.Now().Add(48*time.Hour))
	api := &fakeESA{
		entries: []*esa.ListCertificatesResponseBodyResult{testEntry("stored", leaf)},
		certs:   map[string]string{"stored": string(fullchain)},
		status:  "OK",
	}
	if err := testAction(api).Update(context.Background(), fullchain, key, testCertificate()); err != nil {
		t.Fatal(err)
	}
	if len(api.sets) != 0 {
		t.Fatalf("already stored certificate uploaded again: %+v", api.sets)
	}
}

func TestRefuseToReplaceNewerCertificate(t *testing.T) {
	oldPEM, _, oldLeaf := testMaterial(t, time.Now().Add(72*time.Hour))
	fullchain, key, _ := testMaterial(t, time.Now().Add(48*time.Hour))
	api := &fakeESA{
		entries: []*esa.ListCertificatesResponseBodyResult{testEntry("newer", oldLeaf)},
		certs:   map[string]string{"newer": string(oldPEM)},
	}
	err := testAction(api).Update(context.Background(), fullchain, key, testCertificate())
	if err == nil || !strings.Contains(err.Error(), "expires no earlier") || len(api.sets) != 0 {
		t.Fatalf("expected downgrade rejection, got err=%v sets=%d", err, len(api.sets))
	}
}

func TestCertificateFailureIsReported(t *testing.T) {
	fullchain, key, _ := testMaterial(t, time.Now().Add(48*time.Hour))
	api := &fakeESA{certs: map[string]string{}, status: "ApplyFailed"}
	err := testAction(api).Update(context.Background(), fullchain, key, testCertificate())
	if err == nil || !strings.Contains(err.Error(), "ApplyFailed") {
		t.Fatalf("expected failed ESA status, got %v", err)
	}
}

func TestTopLevelCertificateStatusIsAccepted(t *testing.T) {
	fullchain, key, _ := testMaterial(t, time.Now().Add(48*time.Hour))
	api := &fakeESA{certs: map[string]string{}, status: "OK", outerStatus: true}
	if err := testAction(api).Update(context.Background(), fullchain, key, testCertificate()); err != nil {
		t.Fatal(err)
	}
}

func managedEntries(t *testing.T, n int) (*fakeESA, []byte, []byte) {
	t.Helper()
	oldPEM, _, oldLeaf := testMaterial(t, time.Now().Add(24*time.Hour))
	fullchain, key, _ := testMaterial(t, time.Now().Add(48*time.Hour))
	api := &fakeESA{certs: make(map[string]string), status: "OK"}
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("old-%d", i)
		entry := testEntry(id, oldLeaf)
		entry.Name = ptr(fmt.Sprintf("certdx-123-web-version-%d", i))
		entry.CreateTime = ptr(fmt.Sprintf("2026-01-%02d 00:00:00", i))
		api.entries = append(api.entries, entry)
		api.certs[id] = string(oldPEM)
	}
	return api, fullchain, key
}

func TestQuotaPrunesOldestBeforeAndAfterUpload(t *testing.T) {
	api, fullchain, key := managedEntries(t, 4)
	manual := &esa.ListCertificatesResponseBodyResult{
		Id: ptr("manual"), Type: ptr("upload"), Name: ptr("operator-upload"),
		SAN: ptr("other.example.com"),
	}
	api.entries = append(api.entries, manual)
	if err := testAction(api).Update(context.Background(), fullchain, key, testCertificate()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(api.events, ","); got != "delete:old-1,set,delete:old-2" {
		t.Fatalf("unexpected operation order: %s", got)
	}
	if len(api.entries) != 4 {
		t.Fatalf("expected three certdx certificates and the manual upload, got %d entries", len(api.entries))
	}
	if !slices.Contains(api.entries, manual) {
		t.Fatal("manual certificate was removed")
	}
	for _, id := range []string{"old-3", "old-4", "new-cert-1"} {
		if _, ok := api.certs[id]; !ok {
			t.Fatalf("certificate %s was unexpectedly deleted", id)
		}
	}
}

func TestQuotaPreservesLatestCertificateForOtherSANs(t *testing.T) {
	api, fullchain, key := managedEntries(t, 4)
	other := &esa.ListCertificatesResponseBodyResult{
		Id: ptr("other-domain"), Type: ptr("upload"), Name: ptr("certdx-123-other-domain"),
		SAN: ptr("other.example.com"), CreateTime: ptr("2025-01-01 00:00:00"),
	}
	api.entries = append(api.entries, other)
	if err := testAction(api).Update(context.Background(), fullchain, key, testCertificate()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(api.deletes, ","); got != "old-1,old-2,old-3" {
		t.Fatalf("deleted %s; expected only old versions of the updated SANs", got)
	}
	if !slices.Contains(api.entries, other) {
		t.Fatal("the only certdx certificate for another SAN set was deleted")
	}
}

func TestStoredCertificateIsReusedAndOldVersionsPruned(t *testing.T) {
	api, _, _ := managedEntries(t, 4)
	fullchain, key, leaf := testMaterial(t, time.Now().Add(48*time.Hour))
	api.entries[3].FingerprintSha256 = ptr(fingerprint(leaf))
	api.certs["old-4"] = string(fullchain)
	if err := testAction(api).Update(context.Background(), fullchain, key, testCertificate()); err != nil {
		t.Fatal(err)
	}
	if len(api.sets) != 0 || strings.Join(api.deletes, ",") != "old-1" {
		t.Fatalf("unexpected upload or cleanup: sets=%d deletes=%v", len(api.sets), api.deletes)
	}
}

func TestConfiguredRetainCount(t *testing.T) {
	api, fullchain, key := managedEntries(t, 4)
	api.entries[2].Name = ptr("certdx-123-another-action-version")
	action := testAction(api)
	action.cfg.RetainCount = 2
	if err := action.Update(context.Background(), fullchain, key, testCertificate()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(api.deletes, ","); got != "old-1,old-2,old-3" {
		t.Fatalf("configured retention deleted %s, want three oldest site uploads", got)
	}
	if len(api.entries) != 2 {
		t.Fatalf("retained %d certificates, want 2", len(api.entries))
	}
}

func TestFailedUploadOnlyRemovesMinimumForQuota(t *testing.T) {
	api, fullchain, key := managedEntries(t, 5)
	api.setErr = errors.New("upload failed")
	err := testAction(api).Update(context.Background(), fullchain, key, testCertificate())
	if err == nil || !strings.Contains(err.Error(), "upload failed") {
		t.Fatalf("expected upload error, got %v", err)
	}
	if got := strings.Join(api.events, ","); got != "delete:old-1" {
		t.Fatalf("unexpected operations after upload failure: %s", got)
	}
}

func TestQuotaDoesNotDeleteLastManagedOrManualUpload(t *testing.T) {
	api, fullchain, key := managedEntries(t, 1)
	for i := 0; i < 4; i++ {
		api.entries = append(api.entries, &esa.ListCertificatesResponseBodyResult{
			Id: ptr(fmt.Sprintf("manual-%d", i)), Name: ptr("operator-upload"), Type: ptr("upload"),
		})
	}
	err := testAction(api).Update(context.Background(), fullchain, key, testCertificate())
	if err == nil || !strings.Contains(err.Error(), "only 0 old versions can be retired safely") {
		t.Fatalf("expected quota safety error, got %v", err)
	}
	if len(api.events) != 0 {
		t.Fatalf("unexpected operations: %v", api.events)
	}
}

func TestDeleteFailureStopsUpload(t *testing.T) {
	api, fullchain, key := managedEntries(t, 5)
	api.deleteErr = errors.New("permission denied")
	err := testAction(api).Update(context.Background(), fullchain, key, testCertificate())
	if err == nil || !strings.Contains(err.Error(), "permission denied") || len(api.sets) != 0 {
		t.Fatalf("expected deletion error before upload, got err=%v sets=%d", err, len(api.sets))
	}
}
