// Package retry provides a small retry helper used across certdx for
// ACME obtain attempts, HTTP cert requests, and Tencent Cloud /
// Kubernetes API calls.
//
// Semantics:
//
//   - Do(ctx, n, work) runs work up to n+1 times — the first attempt
//     plus n additional retries. n=0 means "try once".
//   - Between attempts Do sleeps for [Interval] (15s by default).
//   - The sleep is ctx-aware: if ctx fires, Do returns ctx.Err()
//     wrapped, without sleeping out the full interval.
//   - If work fails in under a second, Do bails out immediately on the
//     assumption that the failure is not transient and retrying would
//     just busy-loop. This early-bail is preserved verbatim from the
//     pre-refactor pkg/utils.Retry — it is intentional, not a bug.
package retry

import (
	"context"
	"fmt"
	"time"

	"pkg.para.party/certdx/pkg/logging"
)

// Interval is the delay between retry attempts.
const Interval = 15 * time.Second

// fastFailThreshold is the elapsed-time floor below which Do gives up
// instead of retrying. Failures that arrive faster than this are
// treated as deterministic (programming or config error) rather than
// transient.
const fastFailThreshold = time.Second

// Do runs work up to retryCount additional times after the first
// attempt, sleeping [Interval] between attempts. It returns nil as
// soon as work returns nil. If work fails in under [fastFailThreshold]
// on any attempt, Do gives up immediately. ctx cancellation is
// honored: a sleep that would have run during ctx-Done returns
// ctx.Err() wrapped.
func Do(ctx context.Context, retryCount int, work func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var err error
	for attempt := 0; ; attempt++ {
		begin := time.Now()
		err = work()
		if err == nil {
			return nil
		}

		if elapsed := time.Since(begin); elapsed < fastFailThreshold {
			return fmt.Errorf("errored too fast, give up retry. last error is: %w", err)
		}

		logging.Warn("Retry %d/%d errored: %s", attempt, retryCount, err)

		if attempt >= retryCount {
			break
		}

		select {
		case <-time.After(Interval):
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		}
	}

	return fmt.Errorf("errored too many times, give up retry. last error is: %w", err)
}
