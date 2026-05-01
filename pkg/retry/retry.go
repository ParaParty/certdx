// Package retry provides a small retry helper used across certdx for ACME
// obtain attempts, HTTP cert requests, and Tencent Cloud / Kubernetes API
// calls.
//
// The semantics are intentionally preserved verbatim from the previous
// implementation in pkg/utils so callers see no behavior change. In
// particular, [Do] gives up early if an attempt fails in under a second —
// the assumption is that a sub-second failure is a programming error rather
// than a transient one and retrying would be busy-looping.
package retry

import (
	"fmt"
	"time"

	"pkg.para.party/certdx/pkg/logging"
)

// Do runs work up to retryCount additional times after the first attempt,
// sleeping 15 seconds between attempts. It returns nil as soon as work
// returns nil. If work fails in under a second on any attempt, Do gives up
// immediately on the assumption that the failure is not transient.
func Do(retryCount int, work func() error) error {
	var err error

	i := 0
	for {
		begin := time.Now()
		err = work()
		if err == nil {
			return nil
		}

		if elapsed := time.Since(begin); elapsed < time.Second {
			return fmt.Errorf("errored too fast, give up retry. last error is: %w", err)
		}

		logging.Warn("Retry %d/%d errored, err: %s", i, retryCount, err)

		if i > retryCount {
			break
		}

		i++
		time.Sleep(15 * time.Second)
	}

	return fmt.Errorf("errored too many times, give up retry. last error is: %w", err)
}
