package utils

import (
	"fmt"
	"time"

	"pkg.para.party/certdx/pkg/logging"
)

func Retry(retryCount int, work func() error) error {
	var err error

	i := 0
	for {
		begin := time.Now()
		err = work()
		if err == nil {
			return nil
		}

		if elapsed := time.Since(begin); elapsed < time.Second {
			return fmt.Errorf("errored too fast, give up retry. last error is: %w", err)
		}

		logging.Warn("Retry %d/%d errored, err: %s", i, retryCount, err)

		if i > retryCount {
			break
		}

		i++
		time.Sleep(15 * time.Second)
	}

	return fmt.Errorf("errored too many times, give up retry. last error is: %w", err)
}
