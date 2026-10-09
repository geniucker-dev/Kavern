//go:build !linux

package main

func platformResources() (*int, *uint64, *int64) { return nil, nil, nil }
func platformHost() map[string]string {
	return map[string]string{"resource_metrics": "Linux process CPU/RSS/FD metrics unavailable"}
}
