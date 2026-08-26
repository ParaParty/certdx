package tencentcloud

import (
	"fmt"

	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
)

// Import this package for its side effect to link the tencentCloud
// update action into a binary.
func init() {
	client.RegisterUpdateAction(config.UPDATE_ACTION_TENCENT_CLOUD,
		func(cfg config.UpdateActionConfig, cc *config.ClientConfig) (client.UpdateAction, error) {
			actionCfg, ok := cfg.(*config.TencentCloudAction)
			if !ok {
				return nil, fmt.Errorf("expected *config.TencentCloudAction, got %T", cfg)
			}

			profile, ok := cc.FindTencentCloudProfile(actionCfg.Profile)
			if !ok {
				return nil, fmt.Errorf("no such tencentCloud profile: %s", actionCfg.Profile)
			}

			return New(actionCfg, profile)
		})
}
