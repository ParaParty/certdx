package utils

import (
	"fmt"
	"os"
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

		if i < retryCount {
			break
		}

		i++
		time.Sleep(15 * time.Second)
	}

	return fmt.Errorf("errored too many times, give up retry. last error is: %w", err)
}

func SameCert(arr1, arr2 []string) bool {
	if len(arr1) != len(arr2) {
		return false
	}

	if len(arr1) == 0 {
		return true
	}

Next:
	for _, i := range arr1 {
		for _, j := range arr2 {
			if i == j {
				continue Next
			}
		}

		return false
	}

	return true
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
