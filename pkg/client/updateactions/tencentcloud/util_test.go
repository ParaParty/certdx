package tencentcloud

import (
	"fmt"
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

func sdkErr(code string) error {
	return txerr.NewTencentCloudSDKError(code, "", "req")
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

// TestParseTxcTimeUsesBeijingZone locks the zone of the zone-less layout:
// Tencent Cloud reports Beijing time, so parsing it as UTC made it compare
// eight hours off against a certificate's real NotAfter.
func TestParseTxcTimeUsesBeijingZone(t *testing.T) {
	got, ok := parseTxcTime(ptr("2026-01-02 03:04:05"))
	if !ok {
		t.Fatal("expected tencent cloud layout to parse")
	}
	want := time.Date(2026, 1, 1, 19, 4, 5, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("parseTxcTime = %s, want %s", got, want)
	}

	same, ok := parseTxcTime(ptr("2026-01-02T03:04:05+08:00"))
	if !ok {
		t.Fatal("expected RFC3339 layout to parse")
	}
	if !got.Equal(same) {
		t.Fatalf("mixed layouts disagree: %s != %s", got, same)
	}
}

func TestLeafNotAfter(t *testing.T) {
	notAfter := time.Date(2027, 3, 4, 5, 6, 7, 0, time.UTC)
	fullchain := selfSignedPEM(t, notAfter)

	// A second certificate (the issuer) must not be mistaken for the leaf.
	fullchain = append(fullchain, selfSignedPEM(t, notAfter.Add(365*24*time.Hour))...)

	got, err := leafNotAfter(fullchain)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(notAfter) {
		t.Fatalf("leafNotAfter = %s, want %s", got, notAfter)
	}

	if _, err := leafNotAfter([]byte("not pem")); err == nil {
		t.Fatal("expected an error for data without a certificate")
	}
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
		{sdkErr("UnauthorizedOperation"), true},
		{fmt.Errorf("wrapped: %w", sdkErr("UnauthorizedOperation.CamNoAuth")), true},
		{sdkErr("AuthFailure.UnauthorizedOperation"), true},
		{sdkErr("AuthFailure.SecretIdNotFound"), false},
		{sdkErr("InternalError"), false},
	}
	for _, c := range cases {
		if got := isTxcPermissionError(c.err); got != c.want {
			t.Fatalf("isTxcPermissionError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestIsTransientTxcError(t *testing.T) {
	cases := []struct {
		err       error
		transient bool
	}{
		{nil, false},
		{fmt.Errorf("plain"), false},
		{sdkErr("RequestLimitExceeded"), true},
		{fmt.Errorf("wrapped: %w", sdkErr("InternalError.BackendError")), true},
		{txerr.NewTencentCloudSDKError("ClientError.HttpStatusCodeError", "503", "req"), true},
		{sdkErr("RequestLimitExceeded.GlobalThrottling"), true},
		{sdkErr(codeCertificateDeployHasPending), true},
		{sdkErr(codeCertificateExists), false},
		{sdkErr("AuthFailure.SecretIdNotFound"), false},
		{fmt.Errorf("%w: no deploy record", errTxcRetryable), true},
	}

	for _, c := range cases {
		if got := isTransientTxcError(c.err); got != c.transient {
			t.Fatalf("isTransientTxcError(%v) = %v, want %v", c.err, got, c.transient)
		}
	}
}

func TestIsNothingBoundError(t *testing.T) {
	for _, code := range []string{codeCertificateNotDeployInstance, codeCertificateDeployInstanceEmpty} {
		if !isNothingBoundError(fmt.Errorf("wrapped: %w", sdkErr(code))) {
			t.Fatalf("expected %s to mean nothing is bound", code)
		}
	}
	if isNothingBoundError(sdkErr(codeCertificateExists)) || isNothingBoundError(nil) {
		t.Fatal("expected other errors not to mean nothing is bound")
	}
}
