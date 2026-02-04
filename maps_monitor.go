package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// ProcessMapsEntry stores cached /proc/pid/maps data for a process
type ProcessMapsEntry struct {
	PID         uint32
	Maps        string    // Full /proc/pid/maps content
	LastUpdated time.Time
	DeathTime   time.Time // Zero if still alive
	Cmdline     string
	Exe         string
}

// ProcessMapsCache is a thread-safe cache for process maps
type ProcessMapsCache struct {
	mu      sync.RWMutex
	entries map[uint32]*ProcessMapsEntry
}

// NewProcessMapsCache creates a new ProcessMapsCache
func NewProcessMapsCache() *ProcessMapsCache {
	return &ProcessMapsCache{
		entries: make(map[uint32]*ProcessMapsEntry),
	}
}

// Get returns the maps for a PID if available
func (c *ProcessMapsCache) Get(pid uint32) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.entries[pid]; ok {
		return entry.Maps, true
	}
	return "", false
}

// Update adds or updates a process entry in the cache
func (c *ProcessMapsCache) Update(pid uint32, maps, cmdline, exe string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[pid] = &ProcessMapsEntry{
		PID:         pid,
		Maps:        maps,
		LastUpdated: time.Now(),
		Cmdline:     cmdline,
		Exe:         exe,
	}
}

// MarkDead sets the DeathTime for a process
func (c *ProcessMapsCache) MarkDead(pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[pid]; ok {
		if entry.DeathTime.IsZero() {
			entry.DeathTime = time.Now()
		}
	}
}

// Cleanup removes expired entries based on TTL
func (c *ProcessMapsCache) Cleanup(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for pid, entry := range c.entries {
		if !entry.DeathTime.IsZero() && now.Sub(entry.DeathTime) > ttl {
			delete(c.entries, pid)
		}
	}
}

// TrackedPIDs returns a list of PIDs that are still alive (DeathTime is zero)
func (c *ProcessMapsCache) TrackedPIDs() []uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var pids []uint32
	for pid, entry := range c.entries {
		if entry.DeathTime.IsZero() {
			pids = append(pids, pid)
		}
	}
	return pids
}

// ScanProc scans /proc for PIDs matching the pattern
func ScanProc(pattern *regexp.Regexp) []uint32 {
	var pids []uint32

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return pids
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // Not a numeric directory
		}

		cmdline := ReadProcCmdline(uint32(pid))
		exe := ReadProcExe(uint32(pid))

		if pattern.MatchString(cmdline) || pattern.MatchString(exe) {
			pids = append(pids, uint32(pid))
		}
	}

	return pids
}

// ReadProcMaps reads /proc/pid/maps
func ReadProcMaps(pid uint32) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "maps"))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ReadProcCmdline reads /proc/pid/cmdline
func ReadProcCmdline(pid uint32) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "cmdline"))
	if err != nil {
		return ""
	}
	return string(data)
}

// ReadProcExe reads the /proc/pid/exe symlink
func ReadProcExe(pid uint32) string {
	target, err := os.Readlink(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "exe"))
	if err != nil {
		return ""
	}
	return target
}

// ProcessExists checks if /proc/pid exists
func ProcessExists(pid uint32) bool {
	_, err := os.Stat(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10)))
	return err == nil
}

// RunProcessScanner runs the background process scanner
func RunProcessScanner(ctx context.Context, pattern *regexp.Regexp, ttl time.Duration, cache *ProcessMapsCache) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Discover new matching processes
			newPIDs := ScanProc(pattern)
			for _, pid := range newPIDs {
				maps, err := ReadProcMaps(pid)
				if err == nil {
					cache.Update(pid, maps, ReadProcCmdline(pid), ReadProcExe(pid))
				}
			}

			// Update maps for tracked processes and mark dead ones
			for _, pid := range cache.TrackedPIDs() {
				if ProcessExists(pid) {
					maps, err := ReadProcMaps(pid)
					if err == nil {
						cache.Update(pid, maps, ReadProcCmdline(pid), ReadProcExe(pid))
					}
				} else {
					cache.MarkDead(pid)
				}
			}

			// Cleanup expired entries
			cache.Cleanup(ttl)
		}
	}
}
