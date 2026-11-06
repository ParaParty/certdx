package aliesa

import (
	"fmt"

	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
)

// Import this package for its side effect to link the aliESA update action
// into a binary.
func init() {
	client.RegisterUpdateAction(config.UPDATE_ACTION_ALI_ESA,
		func(cfg config.UpdateActionConfig, cc *config.ClientConfig) (client.UpdateAction, error) {
			actionCfg, ok := cfg.(*config.AliESAAction)
			if !ok {
				return nil, fmt.Errorf("expected *config.AliESAAction, got %T", cfg)
			}
			profile, ok := cc.FindAliESAProfile(actionCfg.Profile)
			if !ok {
				return nil, fmt.Errorf("no such aliESA profile: %s", actionCfg.Profile)
			}
			return New(actionCfg, profile)
		})
}
