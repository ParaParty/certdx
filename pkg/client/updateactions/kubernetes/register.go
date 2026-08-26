package kubernetes

import (
	"fmt"

	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
)

// Import this package for its side effect to link the kubernetes update
// action into a binary.
func init() {
	client.RegisterUpdateAction(config.UPDATE_ACTION_KUBERNETES,
		func(cfg config.UpdateActionConfig, cc *config.ClientConfig) (client.UpdateAction, error) {
			actionCfg, ok := cfg.(*config.KubernetesAction)
			if !ok {
				return nil, fmt.Errorf("expected *config.KubernetesAction, got %T", cfg)
			}

			profile, ok := cc.FindKubernetesProfile(actionCfg.Profile)
			if !ok {
				return nil, fmt.Errorf("no such kubernetes profile: %s", actionCfg.Profile)
			}

			return New(profile)
		})
}
