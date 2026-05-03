package cli

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"pkg.para.party/certdx/pkg/logging"
)

// WaitForShutdown blocks until SIGINT or SIGTERM arrives, then invokes
// stop in a goroutine and waits up to forceTimeout for it to return.
//
//   - A second signal during graceful shutdown escalates to a hard exit
//     via logging.Fatal.
//   - If stop does not return within forceTimeout, the process is also
//     forced to exit.
func WaitForShutdown(stop func(), forceTimeout time.Duration) {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	<-sig

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-sig:
		logging.Fatal("Forced shutdown")
	case <-time.After(forceTimeout):
		logging.Fatal("Graceful shutdown timed out after %s", forceTimeout)
	}
}
