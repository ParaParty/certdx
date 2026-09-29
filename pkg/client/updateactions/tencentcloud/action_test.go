package tencentcloud

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	txssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/retry"
)

// txcLayout formats a time the way the SSL API reports CertEndTime.
func txcLayout(t time.Time) string {
	return t.In(txcTimeZone).Format(txcTimeLayout)
}

func selfSignedPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func cert(id string, end time.Time, sans ...string) *txssl.Certificates {
	c := &txssl.Certificates{
		CertificateId: ptr(id),
		CertEndTime:   ptr(txcLayout(end)),
	}
	for _, s := range sans {
		c.CertSANs = append(c.CertSANs, ptr(s))
	}
	return c
}

// fakeSSL is an in-memory sslAPI. Each Update/Describe call pops the next
// scripted result; running out of script fails the test.
type fakeSSL struct {
	t *testing.T

	mu           sync.Mutex
	certificates []*txssl.Certificates
	describeErrs []error

	updateResults []updateResult
	updateReqs    []*txssl.UpdateCertificateInstanceRequest

	recordResults []recordResult
	recordReqs    int
}

type updateResult struct {
	deployRecordID uint64
	err            error
}

type recordResult struct {
	detail *txssl.DescribeHostUpdateRecordDetailResponseParams
	err    error
}

func (f *fakeSSL) DescribeCertificatesWithContext(_ context.Context, req *txssl.DescribeCertificatesRequest) (*txssl.DescribeCertificatesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.describeErrs) > 0 {
		err := f.describeErrs[0]
		f.describeErrs = f.describeErrs[1:]
		return nil, err
	}

	resp := txssl.NewDescribeCertificatesResponse()
	resp.Response = &txssl.DescribeCertificatesResponseParams{RequestId: ptr("req")}
	if *req.Offset == 0 {
		resp.Response.Certificates = f.certificates
	}
	return resp, nil
}

func (f *fakeSSL) UpdateCertificateInstanceWithContext(_ context.Context, req *txssl.UpdateCertificateInstanceRequest) (*txssl.UpdateCertificateInstanceResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateReqs = append(f.updateReqs, req)
	if len(f.updateResults) == 0 {
		f.t.Fatalf("unexpected UpdateCertificateInstance call #%d", len(f.updateReqs))
	}
	res := f.updateResults[0]
	f.updateResults = f.updateResults[1:]
	if res.err != nil {
		return nil, res.err
	}

	resp := txssl.NewUpdateCertificateInstanceResponse()
	resp.Response = &txssl.UpdateCertificateInstanceResponseParams{
		DeployRecordId: &res.deployRecordID,
		RequestId:      ptr("req"),
	}
	return resp, nil
}

func (f *fakeSSL) DescribeHostUpdateRecordDetailWithContext(_ context.Context, _ *txssl.DescribeHostUpdateRecordDetailRequest) (*txssl.DescribeHostUpdateRecordDetailResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordReqs++
	if len(f.recordResults) == 0 {
		f.t.Fatalf("unexpected DescribeHostUpdateRecordDetail call #%d", f.recordReqs)
	}
	res := f.recordResults[0]
	if len(f.recordResults) > 1 {
		f.recordResults = f.recordResults[1:]
	}
	if res.err != nil {
		return nil, res.err
	}

	resp := txssl.NewDescribeHostUpdateRecordDetailResponse()
	resp.Response = res.detail
	return resp, nil
}

func deployed(success int64) recordResult {
	return recordResult{detail: &txssl.DescribeHostUpdateRecordDetailResponseParams{
		TotalCount:        int64Ptr(success),
		SuccessTotalCount: int64Ptr(success),
	}}
}

// fastTimers shrinks the poll and backoff timers for the duration of a test.
func fastTimers(t *testing.T) {
	t.Helper()
	oldPoll, oldBackoff := deployPollInterval, transientBackoff
	oldConfirm, oldAppear := deployConfirmTimeout, deployRecordAppearTimeout
	deployPollInterval = time.Millisecond
	transientBackoff = time.Millisecond
	deployConfirmTimeout = 200 * time.Millisecond
	deployRecordAppearTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		deployPollInterval, transientBackoff = oldPoll, oldBackoff
		deployConfirmTimeout, deployRecordAppearTimeout = oldConfirm, oldAppear
	})
}

var testDomains = []string{"example.com", "www.example.com"}

// fixture returns an action backed by a fake holding the certificate the
// resources serve now, plus the renewed material expiring at newEnd.
func fixture(t *testing.T) (*Action, *fakeSSL, []byte, time.Time) {
	t.Helper()
	fastTimers(t)

	newEnd := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	fake := &fakeSSL{
		t: t,
		certificates: []*txssl.Certificates{
			cert("current", newEnd.Add(-60*24*time.Hour), "www.example.com", "example.com"),
			cert("previous", newEnd.Add(-120*24*time.Hour), "example.com", "www.example.com"),
			cert("other", newEnd.Add(-60*24*time.Hour), "other.example.com"),
		},
	}
	action := &Action{
		cfg:    &config.TencentCloudAction{ResourceTypes: []string{"cdn"}},
		client: fake,
	}
	return action, fake, selfSignedPEM(t, newEnd), newEnd
}

func clientCert() *config.ClientCertificate {
	return &config.ClientCertificate{Name: "web", Domains: testDomains}
}

func TestPickCertificates(t *testing.T) {
	newEnd := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	older := cert("older", newEnd.Add(-120*day), "example.com", "www.example.com")
	current := cert("current", newEnd.Add(-60*day), "www.example.com", "example.com")
	stored := cert("stored", newEnd, "example.com", "www.example.com")
	later := cert("later", newEnd.Add(300*day), "example.com", "www.example.com")
	otherDomains := cert("other", newEnd.Add(-10*day), "other.example.com")
	broken := &txssl.Certificates{
		CertificateId: ptr("broken"),
		CertEndTime:   ptr("unknown"),
		CertSANs:      []*string{ptr("example.com"), ptr("www.example.com")},
	}

	all := []*txssl.Certificates{older, current, stored, later, otherDomains, broken, nil, {}}
	old, gotStored := pickCertificates(all, testDomains, newEnd)
	if old != current {
		t.Fatalf("old = %v, want the newest certificate expiring before the renewed one", old)
	}
	if gotStored != stored {
		t.Fatalf("stored = %v, want the certificate expiring with the renewed one", gotStored)
	}

	// The stored copy's CertEndTime has no zone and only second precision;
	// it must still be recognized as the renewed certificate, never as the
	// one to replace.
	skewed := cert("skewed", newEnd.Add(8*time.Hour), "example.com", "www.example.com")
	old, gotStored = pickCertificates([]*txssl.Certificates{skewed}, testDomains, newEnd)
	if old != nil || gotStored != skewed {
		t.Fatalf("pickCertificates(skewed) = (%v, %v), want (nil, skewed)", old, gotStored)
	}

	// A longer-lived certificate is never "old": replacing it would move
	// the resources to a shorter-lived one.
	old, gotStored = pickCertificates([]*txssl.Certificates{later, otherDomains, broken}, testDomains, newEnd)
	if old != nil || gotStored != nil {
		t.Fatalf("pickCertificates(later only) = (%v, %v), want (nil, nil)", old, gotStored)
	}
}

func TestUpdateReplacesAndConfirmsDeploy(t *testing.T) {
	action, fake, fullchain, _ := fixture(t)
	fake.updateResults = []updateResult{{deployRecordID: 42}}
	fake.recordResults = []recordResult{
		{detail: &txssl.DescribeHostUpdateRecordDetailResponseParams{
			TotalCount: int64Ptr(2), RunningTotalCount: int64Ptr(1), SuccessTotalCount: int64Ptr(1),
		}},
		deployed(2),
	}

	if err := action.Update(context.Background(), fullchain, []byte("key"), clientCert()); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if len(fake.updateReqs) != 1 {
		t.Fatalf("UpdateCertificateInstance calls = %d, want 1", len(fake.updateReqs))
	}
	req := fake.updateReqs[0]
	if *req.OldCertificateId != "current" {
		t.Fatalf("OldCertificateId = %q, want current", *req.OldCertificateId)
	}
	if req.CertificatePublicKey == nil || *req.CertificatePublicKey != strings.TrimSpace(string(fullchain)) {
		t.Fatal("expected the renewed fullchain to be uploaded")
	}
	if fake.recordReqs != 2 {
		t.Fatalf("deploy record polls = %d, want 2 (poll until nothing is running)", fake.recordReqs)
	}
}

// A deploy record reporting failed resources is final. Surfacing it slowly
// must not make the action runner replay the upload and deploy.
func TestUpdateFailedDeployIsPermanent(t *testing.T) {
	action, fake, fullchain, _ := fixture(t)
	fake.updateResults = []updateResult{{deployRecordID: 42}}
	fake.recordResults = []recordResult{{detail: &txssl.DescribeHostUpdateRecordDetailResponseParams{
		TotalCount: int64Ptr(2), SuccessTotalCount: int64Ptr(1), FailedTotalCount: int64Ptr(1),
	}}}

	err := action.Update(context.Background(), fullchain, []byte("key"), clientCert())
	if err == nil || !strings.Contains(err.Error(), "1 resource(s) failed to update") {
		t.Fatalf("expected a failed-deploy error, got %v", err)
	}
	if !retry.IsPermanent(err) {
		t.Fatalf("expected the failed deploy to be permanent, got %v", err)
	}
}

func TestUpdateDeployRecordNeverListingResourcesIsPermanent(t *testing.T) {
	action, fake, fullchain, _ := fixture(t)
	fake.updateResults = []updateResult{{deployRecordID: 42}}
	fake.recordResults = []recordResult{{detail: &txssl.DescribeHostUpdateRecordDetailResponseParams{}}}

	err := action.Update(context.Background(), fullchain, []byte("key"), clientCert())
	if err == nil || !strings.Contains(err.Error(), "no resource listed") {
		t.Fatalf("expected an unconfirmed-deploy error, got %v", err)
	}
	if !retry.IsPermanent(err) {
		t.Fatalf("expected the unconfirmed deploy to be permanent, got %v", err)
	}
}

func TestUpdateDeployThatNeverSettlesTimesOut(t *testing.T) {
	action, fake, fullchain, _ := fixture(t)
	fake.updateResults = []updateResult{{deployRecordID: 42}}
	fake.recordResults = []recordResult{{detail: &txssl.DescribeHostUpdateRecordDetailResponseParams{
		TotalCount: int64Ptr(1), RunningTotalCount: int64Ptr(1),
	}}}

	err := action.Update(context.Background(), fullchain, []byte("key"), clientCert())
	if err == nil || !strings.Contains(err.Error(), "timeout confirming deploy record 42") {
		t.Fatalf("expected a deploy confirmation timeout, got %v", err)
	}
	if !retry.IsPermanent(err) {
		t.Fatalf("expected the timeout to be permanent, got %v", err)
	}
}

// Accounts whose CAM policy predates the confirmation poll must not start
// failing a deploy Tencent Cloud accepted.
func TestUpdateWithoutPermissionToConfirmSucceeds(t *testing.T) {
	action, fake, fullchain, _ := fixture(t)
	fake.updateResults = []updateResult{{deployRecordID: 42}}
	fake.recordResults = []recordResult{{err: sdkErr("UnauthorizedOperation")}}

	if err := action.Update(context.Background(), fullchain, []byte("key"), clientCert()); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

// An earlier delivery uploaded the renewed certificate but did not re-bind
// the resources. The upload now fails with CertificateExists, which must
// re-bind to the stored copy instead of reporting a no-op as success.
func TestUpdateRebindsToAlreadyUploadedCertificate(t *testing.T) {
	action, fake, fullchain, newEnd := fixture(t)
	fake.certificates = append(fake.certificates, cert("stored", newEnd, "example.com", "www.example.com"))
	fake.updateResults = []updateResult{
		{err: sdkErr(codeCertificateExists)},
		{deployRecordID: 43},
	}
	fake.recordResults = []recordResult{deployed(1)}

	if err := action.Update(context.Background(), fullchain, []byte("key"), clientCert()); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if len(fake.updateReqs) != 2 {
		t.Fatalf("UpdateCertificateInstance calls = %d, want 2 (upload, then rebind)", len(fake.updateReqs))
	}
	rebind := fake.updateReqs[1]
	if *rebind.OldCertificateId != "current" || rebind.CertificateId == nil || *rebind.CertificateId != "stored" {
		t.Fatalf("rebind request old=%v new=%v, want current -> stored", rebind.OldCertificateId, rebind.CertificateId)
	}
	if rebind.CertificatePublicKey != nil {
		t.Fatal("expected the rebind to reference the stored certificate, not upload material")
	}
	if fake.recordReqs != 1 {
		t.Fatalf("deploy record polls = %d, want 1 (the rebind must be confirmed)", fake.recordReqs)
	}
}

// After a daemon restart the renewed certificate is delivered again while
// the resources already serve it: the rebind finds nothing bound to the old
// certificate, which is success.
func TestUpdateRedeliveryAfterRebindIsNoOp(t *testing.T) {
	action, fake, fullchain, newEnd := fixture(t)
	fake.certificates = append(fake.certificates, cert("stored", newEnd, "example.com", "www.example.com"))
	fake.updateResults = []updateResult{
		{err: sdkErr(codeCertificateExists)},
		{err: sdkErr(codeCertificateNotDeployInstance)},
	}

	if err := action.Update(context.Background(), fullchain, []byte("key"), clientCert()); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestUpdateCertificateExistsWithoutStoredCopyFails(t *testing.T) {
	action, fake, fullchain, _ := fixture(t)
	fake.updateResults = []updateResult{{err: sdkErr(codeCertificateExists)}}

	err := action.Update(context.Background(), fullchain, []byte("key"), clientCert())
	if err == nil || !strings.Contains(err.Error(), "no stored certificate") {
		t.Fatalf("expected an error naming the missing stored certificate, got %v", err)
	}
}

// When the account only holds the renewed certificate there is nothing
// older to re-point, and nothing may be uploaded.
func TestUpdateSkipsWhenOnlyRenewedCertificateIsStored(t *testing.T) {
	action, fake, fullchain, newEnd := fixture(t)
	fake.certificates = []*txssl.Certificates{cert("stored", newEnd, "example.com", "www.example.com")}

	if err := action.Update(context.Background(), fullchain, []byte("key"), clientCert()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(fake.updateReqs) != 0 {
		t.Fatalf("UpdateCertificateInstance calls = %d, want 0", len(fake.updateReqs))
	}
}

func TestUpdateSkipsWhenNothingMatches(t *testing.T) {
	action, fake, fullchain, _ := fixture(t)
	fake.certificates = nil

	if err := action.Update(context.Background(), fullchain, []byte("key"), clientCert()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(fake.updateReqs) != 0 {
		t.Fatalf("UpdateCertificateInstance calls = %d, want 0", len(fake.updateReqs))
	}
}

// A zero DeployRecordId means the deploy task is still being created; the
// SDK contract is to repeat the request.
func TestUpdateRepeatsRequestUntilDeployRecordCreated(t *testing.T) {
	action, fake, fullchain, _ := fixture(t)
	fake.updateResults = []updateResult{{deployRecordID: 0}, {deployRecordID: 42}}
	fake.recordResults = []recordResult{deployed(1)}

	if err := action.Update(context.Background(), fullchain, []byte("key"), clientCert()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(fake.updateReqs) != 2 {
		t.Fatalf("UpdateCertificateInstance calls = %d, want 2", len(fake.updateReqs))
	}
}

// Throttling comes back in well under retry.Do's fast-fail floor, so the
// action has to retry it itself.
func TestUpdateRetriesTransientErrors(t *testing.T) {
	action, fake, fullchain, _ := fixture(t)
	fake.describeErrs = []error{sdkErr("RequestLimitExceeded"), sdkErr("InternalError")}
	fake.updateResults = []updateResult{{err: sdkErr("RequestLimitExceeded")}, {deployRecordID: 42}}
	fake.recordResults = []recordResult{
		{err: sdkErr("InternalError")},
		deployed(1),
	}

	if err := action.Update(context.Background(), fullchain, []byte("key"), clientCert()); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestCallTxcAPIBoundsRetries(t *testing.T) {
	fastTimers(t)

	// A deterministic failure is returned straight away.
	calls := 0
	err := callTxcAPI(context.Background(), "DescribeCertificates", func() error {
		calls++
		return sdkErr("AuthFailure.SecretIdNotFound")
	})
	if err == nil || calls != 1 {
		t.Fatalf("deterministic failure: calls = %d err = %v, want 1 call and an error", calls, err)
	}

	// A transient failure is retried transientRetryCount times, no more.
	calls = 0
	err = callTxcAPI(context.Background(), "DescribeCertificates", func() error {
		calls++
		return sdkErr("RequestLimitExceeded")
	})
	if err == nil || calls != transientRetryCount+1 {
		t.Fatalf("transient failure: calls = %d err = %v, want %d calls and an error", calls, err, transientRetryCount+1)
	}

	// Cancellation stops the backoff.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = callTxcAPI(ctx, "DescribeCertificates", func() error {
		return sdkErr("RequestLimitExceeded")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestUpdateRejectsUnparsableCertificate(t *testing.T) {
	action, fake, _, _ := fixture(t)

	if err := action.Update(context.Background(), []byte("not pem"), []byte("key"), clientCert()); err == nil {
		t.Fatal("expected an error for an unparsable fullchain")
	}
	if len(fake.updateReqs) != 0 {
		t.Fatalf("UpdateCertificateInstance calls = %d, want 0", len(fake.updateReqs))
	}
}
