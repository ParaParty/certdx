//go:build !windows

package tools

import "os"

func currentEUID() int {
	return os.Geteuid()
}
