package utils

import (
	"fmt"
	"os"
	"time"
)

func Retry(retryCount int, work func() error) error {
	var err error

	for i := 0; i < retryCount; i++ {
		begin := time.Now()
		err = work()
		if err == nil {
			return nil
		}

		if elapsed := time.Since(begin); elapsed < 5*time.Millisecond {
			return fmt.Errorf("errored too fast, give up retry. last error is: %w", err)
		}

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
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}
