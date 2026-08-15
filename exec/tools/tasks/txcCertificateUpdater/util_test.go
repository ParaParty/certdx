package txcCertificateUpdater

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	txerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	txssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

func ptr(s string) *string {
	return &s
}

func int64Ptr(v int64) *int64 {
	return &v
}

func TestIsSameStrSetRejectNilItem(t *testing.T) {
	if !isSameStrSetRejectNilItem([]*string{ptr("b"), ptr("a")}, []string{"a", "b"}) {
		t.Fatal("expected equal sets with different order")
	}
	if isSameStrSetRejectNilItem([]*string{ptr("a"), ptr("b")}, []string{"a", "c"}) {
		t.Fatal("expected different sets")
	}
	if isSameStrSetRejectNilItem([]*string{ptr("a"), nil}, []string{"a", "b"}) {
		t.Fatal("expected nil item to reject")
	}
}

func TestIsSameStrSetRejectNilItemPtrArrPtrArr(t *testing.T) {
	if !isSameStrSetRejectNilItemPtrArrPtrArr([]*string{ptr("b"), ptr("a")}, []*string{ptr("a"), ptr("b")}) {
		t.Fatal("expected equal sets with different order")
	}
	if isSameStrSetRejectNilItemPtrArrPtrArr([]*string{ptr("a"), ptr("b")}, []*string{ptr("a"), ptr("c")}) {
		t.Fatal("expected different sets")
	}
	if isSameStrSetRejectNilItemPtrArrPtrArr([]*string{ptr("a"), ptr("b")}, []*string{ptr("a"), nil}) {
		t.Fatal("expected nil item to reject")
	}
}

func TestIsSameStrSetIgnoringNilCanonicalizes(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		same bool
	}{
		{"duplicates in b no longer fake a match", []string{"a.example.com", "b.example.com"},
			[]string{"a.example.com", "a.example.com"}, false},
		{"duplicates on both sides collapse", []string{"a.example.com", "a.example.com", "b.example.com"},
			[]string{"b.example.com", "a.example.com"}, true},
		{"case insensitive", []string{"A.Example.COM"}, []string{"a.example.com"}, true},
		{"trailing root dot ignored", []string{"a.example.com."}, []string{"a.example.com"}, true},
		{"still detects a real difference", []string{"a.example.com"}, []string{"b.example.com"}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isSameStrSetIgnoringNil(c.a, c.b); got != c.same {
				t.Fatalf("isSameStrSetIgnoringNil(%v, %v) = %v, want %v", c.a, c.b, got, c.same)
			}
			if got := isSameStrSetIgnoringNil(c.b, c.a); got != c.same {
				t.Fatalf("isSameStrSetIgnoringNil(%v, %v) = %v, want %v (reversed)", c.b, c.a, got, c.same)
			}
		})
	}
}

func TestParseTxcTime(t *testing.T) {
	if _, ok := parseTxcTime(nil); ok {
		t.Fatal("expected nil timestamp to be rejected")
	}
	if _, ok := parseTxcTime(ptr("not a time")); ok {
		t.Fatal("expected garbage timestamp to be rejected")
	}
	early, ok := parseTxcTime(ptr("2026-01-02 03:04:05"))
	if !ok {
		t.Fatal("expected tencent cloud layout to parse")
	}
	late, ok := parseTxcTime(ptr("2026-02-02T03:04:05Z"))
	if !ok {
		t.Fatal("expected RFC3339 layout to parse")
	}
	if !late.After(early) {
		t.Fatal("expected the later timestamp to compare later")
	}
}

// TestParseTxcTimeUsesBeijingZone locks the zone of the zone-less
// layout: Tencent Cloud reports Beijing time, so parsing it as UTC made
// it compare eight hours off against RFC3339 values carrying an offset.
func TestParseTxcTimeUsesBeijingZone(t *testing.T) {
	got, ok := parseTxcTime(ptr("2026-01-02 03:04:05"))
	if !ok {
		t.Fatal("expected tencent cloud layout to parse")
	}
	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("CST", 8*60*60))
	if !got.Equal(want) {
		t.Fatalf("parseTxcTime = %s, want %s", got, want)
	}

	// The same instant spelled in both layouts must compare equal, and
	// the UTC spelling of a *later* wall clock in Beijing must not.
	same, ok := parseTxcTime(ptr("2026-01-02T03:04:05+08:00"))
	if !ok {
		t.Fatal("expected RFC3339 layout to parse")
	}
	if !got.Equal(same) {
		t.Fatalf("mixed layouts disagree: %s != %s", got, same)
	}
	utcSpelling, ok := parseTxcTime(ptr("2026-01-02T03:04:05Z"))
	if !ok {
		t.Fatal("expected RFC3339 UTC layout to parse")
	}
	if !utcSpelling.After(got) {
		t.Fatalf("expected 03:04:05Z to be after 03:04:05 Beijing, got %s vs %s", utcSpelling, got)
	}
}

func TestPickNewerUploadedCertificate(t *testing.T) {
	domains := []string{"example.com", "www.example.com"}
	oldEnd, ok := parseTxcTime(ptr("2026-09-01 00:00:00"))
	if !ok {
		t.Fatal("failed to parse the fixture expiry")
	}

	stale := cert("stale", "2026-08-01 00:00:00", "www.example.com", "example.com")
	sameDay := cert("same", "2026-09-01 00:00:00", "example.com", "www.example.com")
	renewed := cert("renewed", "2026-12-01 00:00:00", "example.com", "www.example.com")
	newest := cert("newest", "2027-01-01 00:00:00", "www.example.com", "example.com")
	otherDomains := cert("other", "2027-06-01 00:00:00", "other.example.com")
	unparsable := cert("broken", "unknown", "example.com", "www.example.com")
	old := cert("old", "2026-09-01 00:00:00", "example.com", "www.example.com")

	t.Run("stale and equal-expiry candidates are rejected", func(t *testing.T) {
		for _, candidates := range [][]*txssl.Certificates{
			{old, stale},
			{old, sameDay},
			{old, unparsable},
			{old, otherDomains},
			{old},
		} {
			got, err := pickNewerUploadedCertificate(candidates, domains, "old", oldEnd)
			if err == nil {
				t.Fatalf("expected no match, got %q", got)
			}
			if !strings.Contains(err.Error(), "no stored certificate matches") {
				t.Fatalf("unexpected error: %s", err)
			}
		}
	})

	t.Run("newest strictly newer candidate wins", func(t *testing.T) {
		got, err := pickNewerUploadedCertificate(
			[]*txssl.Certificates{old, stale, sameDay, renewed, newest, otherDomains, unparsable, nil},
			domains, "old", oldEnd)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got != "newest" {
			t.Fatalf("picked %q, want \"newest\"", got)
		}
	})

	t.Run("unknown old expiry degrades to newest match", func(t *testing.T) {
		got, err := pickNewerUploadedCertificate([]*txssl.Certificates{old, stale}, domains, "old", time.Time{})
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got != "stale" {
			t.Fatalf("picked %q, want \"stale\"", got)
		}
	})
}

func TestDeployRecordListsResources(t *testing.T) {
	if deployRecordListsResources(nil) {
		t.Fatal("expected a nil detail to list no resource")
	}
	empty := &txssl.DescribeHostUpdateRecordDetailResponseParams{}
	if deployRecordListsResources(empty) {
		t.Fatal("expected an empty detail to list no resource")
	}
	// TotalCount is documented as "0 if unavailable": a populated
	// RecordDetailList alone must still count as resources seen.
	listOnly := &txssl.DescribeHostUpdateRecordDetailResponseParams{
		RecordDetailList: []*txssl.UpdateRecordDetails{{}},
	}
	if !deployRecordListsResources(listOnly) {
		t.Fatal("expected a populated RecordDetailList to count as resources seen")
	}
	countOnly := &txssl.DescribeHostUpdateRecordDetailResponseParams{TotalCount: int64Ptr(2)}
	if !deployRecordListsResources(countOnly) {
		t.Fatal("expected a positive TotalCount to count as resources seen")
	}
}

func TestIsTxcPermissionError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("plain"), false},
		{txerr.NewTencentCloudSDKError("UnauthorizedOperation", "", "req"), true},
		{fmt.Errorf("wrapped: %w", txerr.NewTencentCloudSDKError("UnauthorizedOperation.CamNoAuth", "", "req")), true},
		{txerr.NewTencentCloudSDKError("AuthFailure.UnauthorizedOperation", "", "req"), true},
		{txerr.NewTencentCloudSDKError("AuthFailure.SecretIdNotFound", "", "req"), false},
		{txerr.NewTencentCloudSDKError("InternalError", "", "req"), false},
	}
	for _, c := range cases {
		if got := isTxcPermissionError(c.err); got != c.want {
			t.Fatalf("isTxcPermissionError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func cert(id, end string, sans ...string) *txssl.Certificates {
	c := &txssl.Certificates{
		CertificateId: ptr(id),
		CertEndTime:   ptr(end),
	}
	for _, s := range sans {
		c.CertSANs = append(c.CertSANs, ptr(s))
	}
	return c
}

func TestFindReplacementCertificate(t *testing.T) {
	expiringA := cert("a", "2026-09-01 00:00:00", "example.com", "www.example.com")
	expiringB := cert("b", "2026-09-02 00:00:00", "www.example.com", "example.com")
	renewed := cert("c", "2026-12-01 00:00:00", "example.com", "www.example.com")
	other := cert("d", "2027-01-01 00:00:00", "other.example.com")

	expiringIds := map[string]struct{}{"a": {}, "b": {}}
	activating := []*txssl.Certificates{expiringA, expiringB, other}

	// Two same-SAN expiring certs must not suppress each other.
	for _, c := range []*txssl.Certificates{expiringA, expiringB} {
		got, err := findReplacementCertificate(activating, c, expiringIds)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got != nil {
			t.Fatalf("cert %s: expected no replacement, got %s", *c.CertificateId, *got.CertificateId)
		}
	}

	// A genuinely newer, non-expiring cert is a replacement.
	got, err := findReplacementCertificate(append(activating, renewed), expiringA, expiringIds)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if got == nil || *got.CertificateId != "c" {
		t.Fatalf("expected cert c as replacement, got %v", got)
	}

	// An earlier-expiring same-SAN cert outside the expiring window is
	// not a replacement either.
	older := cert("e", "2026-08-01 00:00:00", "example.com", "www.example.com")
	got, err = findReplacementCertificate([]*txssl.Certificates{older}, expiringA, expiringIds)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if got != nil {
		t.Fatalf("expected no replacement for an older cert, got %s", *got.CertificateId)
	}

	// An unparsable expiry never suppresses a renewal.
	broken := cert("f", "unknown", "example.com", "www.example.com")
	got, err = findReplacementCertificate([]*txssl.Certificates{broken}, expiringA, expiringIds)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if got != nil {
		t.Fatalf("expected no replacement for an unparsable cert end time, got %s", *got.CertificateId)
	}
}

func TestIsTransientTxcError(t *testing.T) {
	cases := []struct {
		err       error
		transient bool
	}{
		{nil, false},
		{fmt.Errorf("plain"), false},
		{txerr.NewTencentCloudSDKError("RequestLimitExceeded", "", "req"), true},
		{fmt.Errorf("wrapped: %w", txerr.NewTencentCloudSDKError("InternalError.BackendError", "", "req")), true},
		{txerr.NewTencentCloudSDKError("ClientError.HttpStatusCodeError", "503", "req"), true},
		{txerr.NewTencentCloudSDKError("RequestLimitExceeded.GlobalThrottling", "", "req"), true},
		{txerr.NewTencentCloudSDKError("FailedOperation.CertificateExists", "", "req"), false},
		{txerr.NewTencentCloudSDKError("AuthFailure.SecretIdNotFound", "", "req"), false},
		{fmt.Errorf("%w: no deploy record", errTxcRetryable), true},
	}

	for _, c := range cases {
		if got := isTransientTxcError(c.err); got != c.transient {
			t.Fatalf("isTransientTxcError(%v) = %v, want %v", c.err, got, c.transient)
		}
	}
}

func TestCallTxcAPIRetriesTransientFastFailures(t *testing.T) {
	r := &TencentCloudCertificateUpdater{ctx: context.Background()}

	// A throttling error returns in well under a second: it must reach
	// the retry budget instead of the fast-fail path.
	calls := 0
	err := r.callTxcAPI(0, "DescribeCertificates", func() error {
		calls++
		return txerr.NewTencentCloudSDKError("RequestLimitExceeded", "", "req")
	})
	if err == nil || strings.Contains(err.Error(), "errored too fast") {
		t.Fatalf("expected a retry-budget failure for a transient error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call with retryCount 0, got %d", calls)
	}

	// A deterministic fast failure still bails out immediately.
	calls = 0
	err = r.callTxcAPI(2, "DescribeCertificates", func() error {
		calls++
		return txerr.NewTencentCloudSDKError("AuthFailure.SecretIdNotFound", "", "req")
	})
	if err == nil || !strings.Contains(err.Error(), "errored too fast") {
		t.Fatalf("expected fast-fail for a deterministic error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call for a fast deterministic failure, got %d", calls)
	}

	// Success short-circuits.
	calls = 0
	if err := r.callTxcAPI(2, "DescribeCertificates", func() error {
		calls++
		return nil
	}); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call on success, got %d", calls)
	}
}

// TestCallTxcAPIDoesNotRetryTerminalErrors locks the fix for the
// storm-retry regression: a confirmed deploy failure surfaces after the
// fast-fail window (the poll runs for tens of seconds), so only the
// terminal marker keeps the whole upload + deploy from being replayed.
func TestCallTxcAPIDoesNotRetryTerminalErrors(t *testing.T) {
	r := &TencentCloudCertificateUpdater{ctx: context.Background()}

	calls := 0
	err := r.callTxcAPI(updateRetryCount, "UpdateCertificateInstance", func() error {
		calls++
		// Outlive the fast-fail floor the way a real deploy poll does.
		time.Sleep(txcFastFailThreshold + 50*time.Millisecond)
		return fmt.Errorf("%w: deploy record 42 for cert %q: 2 resource(s) failed to update", errTxcTerminal, "cert")
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, errTxcTerminal) {
		t.Fatalf("expected the terminal marker to survive wrapping, got %v", err)
	}
	if !strings.Contains(err.Error(), "resource(s) failed to update") {
		t.Fatalf("expected the underlying verdict in the message, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected a terminal failure to run once, got %d calls", calls)
	}
	if isTransientTxcError(err) {
		t.Fatal("a terminal failure must never be classified transient")
	}
}

// TestWaitReplaceTaskDeadlineReportsTaskErrors locks the second half of
// the reporting fix: the deadline branch must name the certificate that
// failed instead of returning a bare context error.
func TestWaitReplaceTaskDeadlineReportsTaskErrors(t *testing.T) {
	r := &TencentCloudCertificateUpdater{}
	r.wg.Add(1) // a handler that never finishes
	r.taskErr = append(r.taskErr, fmt.Errorf("replace cert %q: deploy failed", "web"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := r.WaitReplaceTask(ctx)
	if err == nil {
		t.Fatal("expected an error when the deadline fires")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the context error to be reported, got %v", err)
	}
	if !strings.Contains(err.Error(), `replace cert "web"`) {
		t.Fatalf("expected the failing cert to be named, got %v", err)
	}
}

func TestWaitDeployRecordMissingRecordIsRetryable(t *testing.T) {
	r := &TencentCloudCertificateUpdater{ctx: context.Background()}

	for _, id := range []*uint64{nil, new(uint64)} {
		err := r.waitDeployRecord("cert", id)
		if err == nil || !isTransientTxcError(err) {
			t.Fatalf("expected a retryable error for deploy record %v, got %v", id, err)
		}
	}
}
