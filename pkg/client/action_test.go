package client

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/config"
)

type stubAction struct {
	actionType string
	mu         sync.Mutex
	calls      [][]byte
	err        error
	block      chan struct{}
	called     chan struct{}
}

func newStubAction(actionType string) *stubAction {
	return &stubAction{actionType: actionType, called: make(chan struct{}, 16)}
}

func (s *stubAction) Type() string { return s.actionType }

func (s *stubAction) Update(ctx context.Context, fullchain, key []byte, c *config.ClientCertificate) error {
	s.mu.Lock()
	s.calls = append(s.calls, fullchain)
	err := s.err
	block := s.block
	s.mu.Unlock()

	s.called <- struct{}{}

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (s *stubAction) received() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.calls...)
}

func withRegistry(t *testing.T) {
	t.Helper()
	saved := updateActionFactories
	updateActionFactories = map[string]UpdateActionFactory{}
	t.Cleanup(func() { updateActionFactories = saved })
}

func TestBuildActionsUnregisteredType(t *testing.T) {
	withRegistry(t)

	cert := &config.ClientCertificate{
		Name:    "web",
		Actions: []config.UpdateActionConfig{&config.KubernetesAction{Profile: "cluster-a"}},
	}
	_, err := buildActions(cert, &config.ClientConfig{})
	if err == nil {
		t.Fatal("expected error for unregistered action type")
	}
	if !strings.Contains(err.Error(), "not linked into this binary") {
		t.Fatalf("error wording drifted: %v", err)
	}
}

func TestBuildActionsUsesFactory(t *testing.T) {
	withRegistry(t)

	stub := newStubAction(config.UPDATE_ACTION_FILE)
	RegisterUpdateAction(config.UPDATE_ACTION_FILE, func(cfg config.UpdateActionConfig, cc *config.ClientConfig) (UpdateAction, error) {
		if _, ok := cfg.(*config.FileAction); !ok {
			t.Errorf("factory got %T", cfg)
		}
		return stub, nil
	})

	cert := &config.ClientCertificate{
		Name:    "web",
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: "/tmp"}},
	}
	actions, err := buildActions(cert, &config.ClientConfig{})
	if err != nil {
		t.Fatalf("buildActions: %v", err)
	}
	if len(actions) != 1 || actions[0] != stub {
		t.Fatalf("unexpected actions: %+v", actions)
	}
}

func TestBuildActionsPropagatesFactoryError(t *testing.T) {
	withRegistry(t)

	RegisterUpdateAction(config.UPDATE_ACTION_FILE, func(config.UpdateActionConfig, *config.ClientConfig) (UpdateAction, error) {
		return nil, errors.New("boom")
	})

	cert := &config.ClientCertificate{
		Name:    "web",
		Actions: []config.UpdateActionConfig{&config.FileAction{SavePath: "/tmp"}},
	}
	_, err := buildActions(cert, &config.ClientConfig{})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected factory error, got %v", err)
	}
}

func TestActionRunnerDelivers(t *testing.T) {
	stub := newStubAction(config.UPDATE_ACTION_FILE)
	runner := makeActionRunner(stub, &config.ClientCertificate{Name: "web"}, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.run(ctx)

	runner.notify(certData{Fullchain: []byte("chain"), Key: []byte("key")})

	select {
	case <-stub.called:
	case <-time.After(2 * time.Second):
		t.Fatal("action was never invoked")
	}

	got := stub.received()
	if len(got) != 1 || string(got[0]) != "chain" {
		t.Fatalf("unexpected deliveries: %v", got)
	}
}

// A delivery arriving while the action is busy must replace, not queue.
func TestActionRunnerCoalescesPendingUpdates(t *testing.T) {
	stub := newStubAction(config.UPDATE_ACTION_FILE)
	stub.block = make(chan struct{})
	runner := makeActionRunner(stub, &config.ClientCertificate{Name: "web"}, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.run(ctx)

	runner.notify(certData{Fullchain: []byte("first")})
	select {
	case <-stub.called:
	case <-time.After(2 * time.Second):
		t.Fatal("first delivery never started")
	}

	runner.notify(certData{Fullchain: []byte("second")})
	runner.notify(certData{Fullchain: []byte("third")})
	close(stub.block)

	select {
	case <-stub.called:
	case <-time.After(2 * time.Second):
		t.Fatal("coalesced delivery never ran")
	}

	got := stub.received()
	if len(got) != 2 {
		t.Fatalf("expected 2 deliveries, got %d: %v", len(got), got)
	}
	if string(got[1]) != "third" {
		t.Fatalf("expected the newest cert to win, got %q", got[1])
	}
}

func TestActionRunnerStopsWithContext(t *testing.T) {
	stub := newStubAction(config.UPDATE_ACTION_FILE)
	runner := makeActionRunner(stub, &config.ClientCertificate{Name: "web"}, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runner.run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not stop on context cancellation")
	}
}

// A failing action must not take the runner down with it.
func TestActionRunnerSurvivesFailure(t *testing.T) {
	stub := newStubAction(config.UPDATE_ACTION_FILE)
	stub.err = errors.New("nope")
	runner := makeActionRunner(stub, &config.ClientCertificate{Name: "web"}, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.run(ctx)

	runner.notify(certData{Fullchain: []byte("first")})
	select {
	case <-stub.called:
	case <-time.After(2 * time.Second):
		t.Fatal("first delivery never ran")
	}

	stub.mu.Lock()
	stub.err = nil
	stub.mu.Unlock()

	runner.notify(certData{Fullchain: []byte("second")})
	select {
	case <-stub.called:
	case <-time.After(2 * time.Second):
		t.Fatal("runner stopped after a failed delivery")
	}
}
