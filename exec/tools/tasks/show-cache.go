package tasks

import (
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/server"
)

func ShowCache() {
	cacheFile := server.MakeServerCacheFile()
	err := cacheFile.ReadCacheFile()
	if err != nil {
		logging.Fatal("err: %s", err)
	}

	cacheFile.PrintCertInfo()
}
