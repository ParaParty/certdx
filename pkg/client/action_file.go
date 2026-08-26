package client

import (
	"fmt"

	"pkg.para.party/certdx/pkg/client/updateactions/file"
	"pkg.para.party/certdx/pkg/config"
)

// The file action has no third-party dependencies, so unlike the cloud
// actions it is always linked and registers itself here.
func init() {
	RegisterUpdateAction(config.UPDATE_ACTION_FILE, func(cfg config.UpdateActionConfig, _ *config.ClientConfig) (UpdateAction, error) {
		fileCfg, ok := cfg.(*config.FileAction)
		if !ok {
			return nil, fmt.Errorf("expected *config.FileAction, got %T", cfg)
		}
		return file.New(fileCfg), nil
	})
}
