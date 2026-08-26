package client

import (
	"context"
	"fmt"

	"pkg.para.party/certdx/pkg/client/updateactions/file"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
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

// writeCertAndDoCommand adapts the file action to the legacy per-certificate
// savePath/reloadCommand fields.
func writeCertAndDoCommand(fullchain, key []byte, c *config.ClientCertificate) {
	action := file.New(&config.FileAction{SavePath: c.SavePath, ReloadCommand: c.ReloadCommand})
	if err := action.Update(context.Background(), fullchain, key, c); err != nil {
		logging.Error("Failed to save cert file: %s", err)
	}
}
