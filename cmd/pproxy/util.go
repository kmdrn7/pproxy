package main

import "os"

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func relay(in <-chan os.Signal) <-chan struct{} {
	out := make(chan struct{}, 1)
	go func() {
		for range in {
			select {
			case out <- struct{}{}:
			default:
			}
		}
		close(out)
	}()
	return out
}
