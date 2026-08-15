package txcCertificateUpdater

import (
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
// Tencent Cloud reports Beijing time (UTC+8); parsing them as UTC made
// them compare eight hours off against the RFC3339 values that do carry
// an offset.
var txcTimeZone = time.FixedZone("CST", 8*60*60)

// errTxcRetryable marks a condition the local retry loop must treat as
// transient even though no SDK error code is involved (e.g. a deploy
// task that Tencent Cloud has not created yet).
var errTxcRetryable = errors.New("retryable tencent cloud condition")

// errTxcTerminal is the mirror image of [errTxcRetryable]: a confirmed,
// non-retryable outcome that arrives *after* callTxcAPI's fast-fail
// window. Deploy-record confirmation polls for minutes, so without this
// marker its verdict ("these resources failed", "no record ever
// appeared") looked like a slow, possibly transient failure and the
// whole upload + deploy was replayed until the run budget was gone.
var errTxcTerminal = errors.New("terminal tencent cloud failure")

// isTerminalTxcError reports whether err carries the [errTxcTerminal]
// marker and must therefore never be retried.
func isTerminalTxcError(err error) bool {
	return err != nil && errors.Is(err, errTxcTerminal)
}

// isTxcPermissionError reports whether err is Tencent Cloud refusing the
// action for lack of a CAM permission (as opposed to bad credentials).
// Used to keep an optional, read-only confirmation call from turning a
// successful deploy into a failed run on accounts whose policy predates
// the confirmation step.
func isTxcPermissionError(err error) bool {
	var sdkErr *txerr.TencentCloudSDKError
	if err == nil || !errors.As(err, &sdkErr) {
		return false
	}
	code := sdkErr.Code
	switch {
	case code == "UnauthorizedOperation",
		strings.HasPrefix(code, "UnauthorizedOperation."),
		strings.HasPrefix(code, "AuthFailure.UnauthorizedOperation"),
		strings.Contains(code, "NoPermission"):
		return true
	}
	return false
}

// canonicalizeNames canonicalizes a domain slice exactly the way
// domain.AsKey does — lowercase, trailing root dot trimmed, empties
// dropped, deduplicated — and sorts the result so two sets can be
// compared element-wise.
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
// duplicates on either side can no longer fake a match, and matching is
// case-insensitive / root-dot-insensitive like the rest of the codebase.
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

func isSameStrSetRejectNilItemPtrArrPtrArr(a []*string, b []*string) bool {
	derefA, ok := derefAll(a)
	if !ok {
		return false
	}
	derefB, ok := derefAll(b)
	if !ok {
		return false
	}
	return isSameStrSetIgnoringNil(derefA, derefB)
}

// parseTxcTime parses a Tencent Cloud timestamp. It reports false for a
// nil or unparsable value so callers can stay conservative instead of
// treating an unknown expiry as "far in the future".
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

// isTransientTxcError reports whether err is a Tencent Cloud failure
// worth retrying. Throttling and server-side hiccups come back in well
// under retry.Do's one-second fast-fail floor, so they need to be
// recognized explicitly or the retry budget never engages.
func isTransientTxcError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errTxcRetryable) {
		return true
	}

	var sdkErr *txerr.TencentCloudSDKError
	if !errors.As(err, &sdkErr) {
		return false
	}

	code := sdkErr.Code
	switch {
	case strings.HasPrefix(code, "RequestLimitExceeded"),
		strings.HasPrefix(code, "InternalError"),
		strings.HasPrefix(code, "ClientError.NetworkError"),
		strings.HasPrefix(code, "ClientError.HttpStatusCodeError"),
		strings.Contains(code, "Throttling"):
		return true
	}
	return false
}

// pickNewerUploadedCertificate returns the id of the newest stored
// certificate that covers exactly domains, is not oldCertificateId, and
// expires strictly after oldCertEnd.
//
// The expiry guard matters because the lookup runs with FilterExpiring=0
// — the result set therefore contains expiring certificates too, and
// without the guard a rebind could bind every resource to a certificate
// staler than the one being replaced and then "confirm" that as success.
// A zero oldCertEnd means the expiring certificate's own CertEndTime was
// unparsable; the guard then degrades to "newest parsable match" rather
// than refusing to rebind at all.
func pickNewerUploadedCertificate(certificates []*txssl.Certificates, domains []string,
	oldCertificateId string, oldCertEnd time.Time) (string, error) {
	var (
		newestId  string
		newestEnd time.Time
	)
	for _, c := range certificates {
		if c == nil || c.CertificateId == nil {
			continue
		}
		if *c.CertificateId == oldCertificateId {
			continue
		}
		if !isSameStrSetRejectNilItem(c.CertSANs, domains) {
			continue
		}
		end, ok := parseTxcTime(c.CertEndTime)
		if !ok {
			continue
		}
		if !oldCertEnd.IsZero() && !end.After(oldCertEnd) {
			continue
		}
		if newestId == "" || end.After(newestEnd) {
			newestId, newestEnd = *c.CertificateId, end
		}
	}
	if newestId == "" {
		return "", fmt.Errorf("no stored certificate matches domains %v and expires after %s",
			domains, oldCertEnd.Format(time.RFC3339))
	}
	return newestId, nil
}

// deployRecordListsResources reports whether a host-update record detail
// response mentions at least one resource. TotalCount alone was not
// enough: the SDK documents it as "0 if unavailable", so a response that
// lists resources in RecordDetailList but omits the count used to read
// as "no resource yet" and the poll waited out its whole timeout before
// declaring success without ever confirming anything.
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
