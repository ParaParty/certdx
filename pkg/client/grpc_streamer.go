package client

import (
	"context"
	"sync/atomic"
	"time"

	"pkg.para.party/certdx/pkg/logging"
)

// grpcRetryWindow is the time threshold used to decide whether a
// just-ended stream counts as a "long-lived, stable" connection (in
// which case the retry counter resets) or a flap (in which case we
// back off).
const grpcRetryWindow = 5 * time.Minute

// grpcRetryBackoff is the short delay between reconnect attempts while
// the per-server retry budget has not yet been exhausted.
const grpcRetryBackoff = 15 * time.Second

// GRPC_CLIENT_STATE enumerates the discrete phases of the failover
// state machine that drives GRPCMain.
type GRPC_CLIENT_STATE int

const (
	GRPC_STATE_STOP GRPC_CLIENT_STATE = iota
	GRPC_STATE_MAIN
	GRPC_STATE_FAILOVER
	GRPC_STATE_TRY_FALLBACK
	GRPC_STATE_RESTART_MAIN
)

// grpcStreamer owns one run of the gRPC failover state machine. Its
// fields collect the parameters and per-cycle state that the dispatch
// loop needs; methods named handle* implement each state. The struct
// is re-created per GRPCMain call, so its state is not shared across
// daemon restarts.
type grpcStreamer struct {
	daemon *CertDXClientDaemon

	mainClient    *CertDXgRPCClient
	standbyClient *CertDXgRPCClient
	standbyExists bool

	stateChan chan GRPC_CLIENT_STATE

	mainRetryCount int
	standbyActive  atomic.Bool

	// sessionCtx / sessionCancel are mutated only by the dispatch
	// goroutine in run. They scope every goroutine spawned for a
	// single FAILOVER → TRY_FALLBACK → RESTART_MAIN cycle, derived
	// from the daemon's rootCtx so daemon Stop drains them too.
	sessionCtx    context.Context
	sessionCancel context.CancelFunc
}

func newGRPCStreamer(d *CertDXClientDaemon) *grpcStreamer {
	s := &grpcStreamer{
		daemon:        d,
		mainClient:    MakeCertDXgRPCClient(&d.Config.GRPC.MainServer, d.certs),
		standbyExists: d.Config.GRPC.StandbyServer.Server != "",
		stateChan:     make(chan GRPC_CLIENT_STATE, 1),
	}
	if s.standbyExists {
		s.standbyClient = MakeCertDXgRPCClient(&d.Config.GRPC.StandbyServer, d.certs)
	}
	s.sessionCtx, s.sessionCancel = context.WithCancel(d.rootCtx)
	return s
}

// run is the dispatch loop. It reads state transitions off stateChan
// and invokes the matching handler. Exits when GRPC_STATE_STOP arrives.
func (s *grpcStreamer) run() {
	defer s.daemon.wg.Done()
	defer s.sessionCancel()

	for {
		var state GRPC_CLIENT_STATE
		select {
		case state = <-s.stateChan:
		case <-s.daemon.rootCtx.Done():
			s.sessionCancel()
			return
		}
		logging.Debug("Process grpc client state: %d", state)
		switch state {
		case GRPC_STATE_STOP:
			s.sessionCancel()
			return
		case GRPC_STATE_MAIN:
			s.daemon.wg.Add(1)
			go s.handleMain()
		case GRPC_STATE_FAILOVER:
			// Cancel any leftover cycle and start a fresh one.
			s.sessionCancel()
			s.sessionCtx, s.sessionCancel = context.WithCancel(s.daemon.rootCtx)

			s.standbyActive.Store(true)
			s.daemon.wg.Add(1)
			go s.handleFailover()
			s.sendState(GRPC_STATE_TRY_FALLBACK)
		case GRPC_STATE_TRY_FALLBACK:
			s.daemon.wg.Add(1)
			go s.handleFallback(s.sessionCtx, s.sessionCancel)
			s.sendState(GRPC_STATE_RESTART_MAIN)
		case GRPC_STATE_RESTART_MAIN:
			s.daemon.wg.Add(1)
			go s.handleRestart(s.sessionCtx)
		}
	}
}

func (s *grpcStreamer) sendState(state GRPC_CLIENT_STATE) bool {
	select {
	case s.stateChan <- state:
		return true
	case <-s.daemon.rootCtx.Done():
		return false
	}
}

// handleMain runs one attempt at the main stream. On success the
// retry counter resets; on failure it increments and schedules either
// a retry, a failover to standby, or a sleep-then-retry depending on
// the budget.
func (s *grpcStreamer) handleMain() {
	defer func() {
		s.daemon.wg.Done()
		logging.Debug("Main stream goroutine exit")
	}()

	logging.Info("Starting gRPC main stream")
	startTime := time.Now()
	err := s.mainClient.Stream(s.daemon.rootCtx)
	logging.Info("gRPC main stream stopped: %s", err)
	if _, ok := err.(*killed); ok {
		s.sendState(GRPC_STATE_STOP)
		return
	}

	if time.Now().Before(startTime.Add(grpcRetryWindow)) {
		s.mainRetryCount++
	} else {
		s.mainRetryCount = 0
		s.sendState(GRPC_STATE_MAIN)
		return
	}

	logging.Info("Current main server retry count: %d", s.mainRetryCount)
	if s.mainRetryCount < s.daemon.Config.Common.RetryCount {
		select {
		case <-time.After(grpcRetryBackoff):
			s.sendState(GRPC_STATE_MAIN)
			return
		case <-s.daemon.rootCtx.Done():
			return
		}
	}

	logging.Info("Retry limit for main stream reached")
	s.mainRetryCount = 0
	if s.standbyExists && !s.standbyActive.Load() {
		logging.Info("Start trying standby stream")
		s.sendState(GRPC_STATE_FAILOVER)
	} else {
		logging.Info("Sleep %s", s.daemon.Config.Common.ReconnectInterval)
		s.sendState(GRPC_STATE_RESTART_MAIN)
	}
}

// handleFailover drives the standby gRPC stream while the main is
// dead, retrying with the same backoff as handleMain. It exits when
// sessionCtx is cancelled (main recovered or daemon stopped).
func (s *grpcStreamer) handleFailover() {
	defer func() {
		s.daemon.wg.Done()
		s.standbyActive.Store(false)
		logging.Debug("Standby goroutine exit")
	}()

	standbyRetryCount := 0
	for {
		if s.sessionCtx.Err() != nil {
			return
		}
		logging.Info("Starting gRPC standby stream")
		startTime := time.Now()
		err := s.standbyClient.Stream(s.sessionCtx)
		logging.Info("gRPC standby stream stopped: %s", err)
		if _, ok := err.(*killed); ok {
			return
		}

		if time.Now().Before(startTime.Add(grpcRetryWindow)) {
			standbyRetryCount++
		} else {
			standbyRetryCount = 0
			continue
		}

		logging.Info("Current standby server retry count: %d", standbyRetryCount)
		if standbyRetryCount < s.daemon.Config.Common.RetryCount {
			select {
			case <-time.After(grpcRetryBackoff):
				continue
			case <-s.sessionCtx.Done():
				logging.Debug("Standby goroutine reset")
				return
			}
		}

		logging.Info("Retry limit for standby stream reached, sleep %s", s.daemon.Config.Common.ReconnectInterval)
		standbyRetryCount = 0
		select {
		case <-time.After(s.daemon.Config.Common.ReconnectDuration):
			continue
		case <-s.sessionCtx.Done():
			logging.Debug("Standby goroutine reset")
			return
		}
	}
}

// handleFallback waits for the main client to receive a message (i.e.
// main is alive again). On recovery it kills the standby and cancels
// the session, which signals every other session-bound goroutine
// (handleFailover, handleRestart) to wind down. If sessionCtx fires
// first, fallback exits without action.
func (s *grpcStreamer) handleFallback(sessionCtx context.Context, sessionCancel context.CancelFunc) {
	defer func() {
		s.daemon.wg.Done()
		logging.Debug("Fallback goroutine exit")
	}()
	select {
	case <-*s.mainClient.Received.Load():
		s.standbyClient.Kill()
		sessionCancel()
	case <-sessionCtx.Done():
		logging.Debug("Fallback goroutine reset")
	}
}

// handleRestart sleeps for ReconnectDuration before signalling MAIN
// again. Cancelled by sessionCtx; in that case it exits without
// re-entering MAIN.
func (s *grpcStreamer) handleRestart(sessionCtx context.Context) {
	defer func() {
		s.daemon.wg.Done()
		logging.Debug("Restart goroutine exit")
	}()
	logging.Debug("Reconnect duration is: %s", s.daemon.Config.Common.ReconnectDuration)
	select {
	case <-time.After(s.daemon.Config.Common.ReconnectDuration):
		s.sendState(GRPC_STATE_MAIN)
	case <-sessionCtx.Done():
		logging.Debug("Restart goroutine reset")
		return
	}
}

// GRPCMain runs the gRPC SDS client (with failover) until Stop is
// called. The five-state machine and its state transitions are
// preserved; encapsulating it in grpcStreamer just makes the
// dispatch loop and per-state logic easier to read.
func (r *CertDXClientDaemon) GRPCMain() {
	r.startWatchers()

	s := newGRPCStreamer(r)

	r.wg.Add(1)
	go s.run()

	s.sendState(GRPC_STATE_MAIN)

	<-r.rootCtx.Done()

	s.sendState(GRPC_STATE_STOP)

	logging.Info("Stopping gRPC client")
	s.mainClient.Kill()
	if s.standbyClient != nil {
		s.standbyClient.Kill()
	}
	r.wg.Wait()
}
