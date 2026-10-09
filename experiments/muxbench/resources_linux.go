package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func platformResources() (*int, *uint64, *int64) {
	var fd *int
	var rss *uint64
	var cpu *int64
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		value := len(entries)
		fd = &value
	}
	if data, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 1 {
			pages, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				value := pages * uint64(os.Getpagesize())
				rss = &value
			}
		}
	}
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) == nil {
		value := usage.Utime.Nano() + usage.Stime.Nano()
		cpu = &value
	}
	return fd, rss, cpu
}
func platformHost() map[string]string {
	out := map[string]string{"gogc_env": os.Getenv("GOGC"), "gomemlimit_env": os.Getenv("GOMEMLIMIT")}
	for key, path := range map[string]string{"cpu_quota": "/sys/fs/cgroup/cpu.max", "memory_limit": "/sys/fs/cgroup/memory.max"} {
		if data, err := os.ReadFile(path); err == nil {
			out[key] = strings.TrimSpace(string(data))
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				out["host_memory"] = strings.TrimSpace(line)
				break
			}
		}
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		out["kernel_release"] = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				_, model, ok := strings.Cut(line, ":")
				if ok {
					out["cpu_model"] = strings.TrimSpace(model)
				}
				break
			}
		}
	}
	return out
}
