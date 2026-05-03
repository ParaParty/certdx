package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestAttemptCounts exercises the n+1 attempts contract directly.
func TestAttemptCounts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		retry     int
		wantCalls int
	}{
		{"zero_retry_one_call", 0, 1},
		{"one_retry_two_calls", 1, 2},
		{"three_retries_four_calls", 3, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := Do(context.Background(), tc.retry, func() error {
				calls++
				time.Sleep(fastFailThreshold + 10*time.Millisecond)
				return errors.New("boom")
			})
			if err == nil {
				t.Fatalf("expected an error after exhausting retries")
			}
			if calls != tc.wantCalls {
				t.Fatalf("calls = %d, want %d", calls, tc.wantCalls)
			}
		})
	}
}

// TestSucceedsImmediately verifies the happy path returns nil on the
// first successful attempt.
func TestSucceedsImmediately(t *testing.T) {
	calls := 0
	err := Do(context.Background(), 5, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

// TestFastFail exercises the sub-second early-bail.
func TestFastFail(t *testing.T) {
	calls := 0
	err := Do(context.Background(), 5, func() error {
		calls++
		return errors.New("instant")
	})
	if err == nil {
		t.Fatal("expected fast-fail error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (fast-fail should not retry)", calls)
	}
}

// TestCtxCancelDuringSleep verifies a cancelled ctx breaks the inter-
// attempt sleep and returns ctx.Err()-wrapped without busy-waiting the
// full Interval.
func TestCtxCancelDuringSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	calls := 0
	done := make(chan error, 1)
	go func() {
		done <- Do(ctx, 5, func() error {
			calls++
			time.Sleep(fastFailThreshold + 10*time.Millisecond)
			return errors.New("retry-me")
		})
	}()

	// Wait for the first attempt to fail and the helper to enter the
	// inter-attempt sleep, then cancel.
	time.Sleep(2 * fastFailThreshold)
	cancel()

	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected wrapped context.Canceled, got %v", err)
		}
		if calls < 1 {
			t.Fatalf("expected at least one attempt before cancel, got %d", calls)
		}
	case <-time.After(Interval):
		t.Fatal("Do did not return promptly after ctx cancel")
	}
}

// TestCtxAlreadyDone verifies Do exits immediately when ctx is already
// cancelled, without invoking work.
func TestCtxAlreadyDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	err := Do(ctx, 5, func() error {
		calls++
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("calls = %d, want 0 (work must not run after ctx done)", calls)
	}
}
