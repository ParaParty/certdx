package client

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"pkg.para.party/certdx/pkg/config"
)

// onceRun tracks the first fetch and final action result for each certificate.
type onceRun struct {
	mu             sync.Mutex
	pendingFetches int
	pendingCerts   int
	fetched        chan struct{}
	done           chan struct{}
	errs           []error
}

func newOnceRun(count int) *onceRun {
	return &onceRun{
		pendingFetches: count,
		pendingCerts:   count,
		fetched:        make(chan struct{}),
		done:           make(chan struct{}),
	}
}

func (o *onceRun) fetchFinished(cert *watchingCert, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err != nil {
		o.errs = append(o.errs, fmt.Errorf("certificate %s: %w", cert.Config.Name, err))
		o.pendingCerts--
		if o.pendingCerts == 0 {
			close(o.done)
		}
	}
	o.pendingFetches--
	if o.pendingFetches == 0 {
		close(o.fetched)
	}
}

func (o *onceRun) actionsFinished(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err != nil {
		o.errs = append(o.errs, err)
	}
	o.pendingCerts--
	if o.pendingCerts == 0 {
		close(o.done)
	}
}

func (o *onceRun) result() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return errors.Join(o.errs...)
}

func (r *CertDXClientDaemon) deliverOnce(cert *watchingCert, data certData) error {
	results := make([]error, len(cert.Runners))
	var wg sync.WaitGroup
	for i, runner := range cert.Runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = runner.deliver(r.rootCtx, data)
		}()
	}
	wg.Wait()
	return errors.Join(results...)
}

// RunOnce uses the normal HTTP or gRPC client loop and stops it after all
// first certificate fetches and their update actions have completed.
func (r *CertDXClientDaemon) RunOnce() error {
	if !r.Config.AllActionsOneShot() {
		return fmt.Errorf("one-shot run requires only one-shot update actions")
	}
	if r.Config.Common.Mode != config.CLIENT_MODE_HTTP && r.Config.Common.Mode != config.CLIENT_MODE_GRPC {
		return fmt.Errorf("unsupported mode: %s", r.Config.Common.Mode)
	}
	if len(r.certs) == 0 {
		return fmt.Errorf("client has no initialized certificates")
	}
	r.once = newOnceRun(len(r.certs))

	daemonDone := make(chan struct{})
	var daemonErr error
	go func() {
		defer close(daemonDone)
		if r.Config.Common.Mode == config.CLIENT_MODE_HTTP {
			daemonErr = r.HttpMain()
		} else {
			daemonErr = r.GRPCMain()
		}
	}()
	defer func() {
		r.Stop()
		<-daemonDone
	}()

	var fetchTimeout <-chan time.Time
	if r.Config.Common.Mode == config.CLIENT_MODE_GRPC {
		timer := time.NewTimer(r.Config.Common.ReconnectDuration)
		defer timer.Stop()
		fetchTimeout = timer.C
	}
	select {
	case <-r.once.fetched:
	case <-daemonDone:
		if daemonErr == nil {
			daemonErr = fmt.Errorf("client stopped before the first fetch completed")
		}
		return errors.Join(r.once.result(), daemonErr)
	case <-fetchTimeout:
		return errors.Join(r.once.result(), fmt.Errorf("timed out waiting for certificates from gRPC server"))
	case <-r.rootCtx.Done():
		return errors.Join(r.once.result(), r.rootCtx.Err())
	}

	select {
	case <-r.once.done:
		return r.once.result()
	case <-r.rootCtx.Done():
		return errors.Join(r.once.result(), r.rootCtx.Err())
	}
}
