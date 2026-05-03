package cli

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"pkg.para.party/certdx/pkg/logging"
)

// WaitForShutdown blocks until SIGINT/SIGTERM arrives or errCh reports
// a background service failure. It then invokes stop in a goroutine
// and waits up to forceTimeout for it to return.
//
//   - A second signal during graceful shutdown escalates to a hard exit
//     via logging.Fatal.
//   - If stop does not return within forceTimeout, the process is also
//     forced to exit.
func WaitForShutdown(stop func(), forceTimeout time.Duration, errCh ...<-chan error) error {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	var serviceErr error
	var errs <-chan error
	if len(errCh) > 0 {
		errs = errCh[0]
	}

	select {
	case <-sig:
	case serviceErr = <-errs:
	}

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
		return serviceErr
	case <-sig:
		logging.Fatal("Forced shutdown")
	case <-time.After(forceTimeout):
		logging.Fatal("Graceful shutdown timed out after %s", forceTimeout)
	}
	return serviceErr
}
