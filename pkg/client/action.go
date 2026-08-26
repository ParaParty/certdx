package client

import (
	"context"
	"fmt"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/retry"
)

// UpdateAction delivers a renewed certificate somewhere: to disk, to a
// cloud provider, to a Kubernetes secret. Implementations are registered
// by the binary that links them, so heavy SDK dependencies stay out of
// pkg/client and its other consumers.
type UpdateAction interface {
	Type() string
	Update(ctx context.Context, fullchain, key []byte, c *config.ClientCertificate) error
}

// UpdateActionFactory builds a ready-to-run action from its decoded config.
// The whole client config is passed so the factory can resolve its profile.
type UpdateActionFactory func(cfg config.UpdateActionConfig, cc *config.ClientConfig) (UpdateAction, error)

var updateActionFactories = map[string]UpdateActionFactory{}

// RegisterUpdateAction wires an action type to its implementation. Call it
// from an init function; registration must happen before ClientInit runs.
func RegisterUpdateAction(actionType string, factory UpdateActionFactory) {
	updateActionFactories[actionType] = factory
}

func buildActions(cert *config.ClientCertificate, cc *config.ClientConfig) ([]UpdateAction, error) {
	actions := make([]UpdateAction, 0, len(cert.Actions))

	for _, actionCfg := range cert.Actions {
		factory, ok := updateActionFactories[actionCfg.ActionType()]
		if !ok {
			return nil, fmt.Errorf("certificate %s: update action type %q is configured but not linked into this binary",
				cert.Name, actionCfg.ActionType())
		}

		action, err := factory(actionCfg, cc)
		if err != nil {
			return nil, fmt.Errorf("certificate %s: update action %s: %w", cert.Name, actionCfg.ActionType(), err)
		}
		actions = append(actions, action)
	}

	return actions, nil
}

// actionRunner owns one action for one certificate. It exists so a slow
// cloud API call cannot stall delivery of later certificates: watchUpdate
// hands the material over and moves on.
type actionRunner struct {
	action     UpdateAction
	cert       *config.ClientCertificate
	retryCount int
	// updateChan holds at most one pending delivery; a newer certificate
	// replaces an older one that has not been picked up yet.
	updateChan chan certData
}

func makeActionRunner(action UpdateAction, cert *config.ClientCertificate, retryCount int) *actionRunner {
	return &actionRunner{
		action:     action,
		cert:       cert,
		retryCount: retryCount,
		updateChan: make(chan certData, 1),
	}
}

// notify queues cert for delivery without ever blocking the caller. If a
// delivery is already pending it is dropped in favour of the newer one.
// Only the certificate's watcher goroutine calls this.
func (r *actionRunner) notify(cert certData) {
	select {
	case r.updateChan <- cert:
		return
	default:
	}

	select {
	case <-r.updateChan:
	default:
	}

	select {
	case r.updateChan <- cert:
	default:
	}
}

func (r *actionRunner) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cert := <-r.updateChan:
			r.deliver(ctx, cert)
		}
	}
}

func (r *actionRunner) deliver(ctx context.Context, cert certData) {
	logging.Info("Running %s update action for cert %s", r.action.Type(), r.cert.Name)

	err := retry.Do(ctx, r.retryCount, func() error {
		return r.action.Update(ctx, cert.Fullchain, cert.Key, r.cert)
	})
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		logging.Error("Update action %s failed for cert %s: %s", r.action.Type(), r.cert.Name, err)
		return
	}

	logging.Notice("Update action %s succeeded for cert %s", r.action.Type(), r.cert.Name)
}
