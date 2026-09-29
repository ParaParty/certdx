package tencentcloud

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	txerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	txssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// txcTimeLayout is the timestamp format Tencent Cloud SSL returns in
// CertBeginTime / CertEndTime.
const txcTimeLayout = "2006-01-02 15:04:05"

// txcTimeZone is the zone those zone-less timestamps are expressed in.
// Tencent Cloud reports Beijing time (the SDK documents CertEndTime as
// GMT+8); parsing them as UTC made them compare eight hours off against a
// certificate's real NotAfter.
var txcTimeZone = time.FixedZone("CST", 8*60*60)

const (
	codeCertificateExists              = "FailedOperation.CertificateExists"
	codeCertificateNotDeployInstance   = "FailedOperation.CertificateNotDeployInstance"
	codeCertificateDeployInstanceEmpty = "FailedOperation.CertificateDeployInstanceEmpty"
	codeCertificateDeployHasPending    = "FailedOperation.CertificateDeployHasPendingRecord"
)

// errTxcRetryable marks a condition callTxcAPI must treat as transient even
// though no SDK error code is involved (e.g. a deploy task that Tencent Cloud
// has not created yet).
var errTxcRetryable = errors.New("retryable tencent cloud condition")

// txcErrorCode returns the Tencent Cloud error code carried by err, or "" when
// err is not an SDK error.
func txcErrorCode(err error) string {
	var sdkErr *txerr.TencentCloudSDKError
	if err == nil || !errors.As(err, &sdkErr) {
		return ""
	}
	return sdkErr.Code
}

// isTransientTxcError reports whether err is a Tencent Cloud failure worth
// retrying: throttling, server-side hiccups, network errors, or a deploy
// task that is still being created.
func isTransientTxcError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errTxcRetryable) {
		return true
	}

	code := txcErrorCode(err)
	switch {
	case strings.HasPrefix(code, "RequestLimitExceeded"),
		strings.HasPrefix(code, "InternalError"),
		strings.HasPrefix(code, "ClientError.NetworkError"),
		strings.HasPrefix(code, "ClientError.HttpStatusCodeError"),
		strings.Contains(code, "Throttling"),
		code == codeCertificateDeployHasPending:
		return true
	}
	return false
}

// isTxcPermissionError reports whether err is Tencent Cloud refusing the
// action for lack of a CAM permission (as opposed to bad credentials). Used
// to keep an optional, read-only confirmation call from turning a successful
// deploy into a failure on accounts whose policy predates the confirmation
// step.
func isTxcPermissionError(err error) bool {
	code := txcErrorCode(err)
	switch {
	case code == "UnauthorizedOperation",
		strings.HasPrefix(code, "UnauthorizedOperation."),
		strings.HasPrefix(code, "AuthFailure.UnauthorizedOperation"),
		strings.Contains(code, "NoPermission"):
		return true
	}
	return false
}

// isNothingBoundError reports whether UpdateCertificateInstance refused
// because the old certificate has no resource of the requested types bound
// to it, so there is nothing to re-point.
func isNothingBoundError(err error) bool {
	switch txcErrorCode(err) {
	case codeCertificateNotDeployInstance, codeCertificateDeployInstanceEmpty:
		return true
	}
	return false
}

// canonicalizeNames canonicalizes a domain slice exactly the way
// domain.AsKey does — lowercase, trailing root dot trimmed, empties dropped,
// deduplicated — and sorts the result so two sets can be compared
// element-wise.
func canonicalizeNames(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// isSameStrSetIgnoringNil reports whether a and b denote the same set of
// domain names once canonicalized. Both sides are deduplicated first, so
// duplicates on either side cannot fake a match, and matching is
// case-insensitive and root-dot-insensitive like the rest of the codebase.
func isSameStrSetIgnoringNil(a, b []string) bool {
	ca, cb := canonicalizeNames(a), canonicalizeNames(b)
	if len(ca) != len(cb) {
		return false
	}
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}

func derefAll(in []*string) ([]string, bool) {
	out := make([]string, len(in))
	for i, v := range in {
		if v == nil {
			return nil, false
		}
		out[i] = *v
	}
	return out, true
}

func isSameStrSetRejectNilItem(a []*string, b []string) bool {
	deref, ok := derefAll(a)
	if !ok {
		return false
	}
	return isSameStrSetIgnoringNil(deref, b)
}

// parseTxcTime parses a Tencent Cloud timestamp. It reports false for a nil
// or unparsable value so callers can stay conservative instead of treating
// an unknown expiry as a real one.
func parseTxcTime(raw *string) (time.Time, bool) {
	if raw == nil {
		return time.Time{}, false
	}
	s := strings.TrimSpace(*raw)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.ParseInLocation(txcTimeLayout, s, txcTimeZone); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// parseLeaf returns the first certificate in a PEM fullchain, which is the
// leaf.
func parseLeaf(fullchain []byte) (*x509.Certificate, error) {
	rest := fullchain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no certificate in PEM data")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
}

// sha1Fingerprint returns the lowercase hex SHA-1 of cert's DER encoding,
// the form normalizeFingerprint brings CertFingerprint into.
func sha1Fingerprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// normalizeFingerprint lowercases a hex fingerprint and drops the colon or
// space separators it may be formatted with.
func normalizeFingerprint(fp string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(fp)))
}

// deployRecordListsResources reports whether a host-update record detail
// response mentions at least one resource. TotalCount alone is not enough:
// the SDK documents it as "0 if unavailable", so a response listing
// resources in RecordDetailList but omitting the count would read as "no
// resource yet".
func deployRecordListsResources(detail *txssl.DescribeHostUpdateRecordDetailResponseParams) bool {
	if detail == nil {
		return false
	}
	return int64OrZero(detail.TotalCount) > 0 || len(detail.RecordDetailList) > 0
}

func int64OrZero(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func stringOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
