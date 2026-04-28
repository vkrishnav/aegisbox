//go:build linux

package runtime

import (
	"fmt"
	"os/exec"
	"syscall"

	"github.com/vamsiv/aegisbox/pkg/image"
)

// applyResourceLimits sets up Linux namespace isolation and logs cgroup intent.
// Full cgroups v2 enforcement (memory/CPU hard limits) requires /sys/fs/cgroup
// write access and is left as a stub for the container manager layer.
func applyResourceLimits(cmd *exec.Cmd, limits image.ResourceLimits) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	}
	if limits.MemoryBytes > 0 {
		fmt.Printf("[aegisbox] cgroup target: memory=%dB cpu=%.1f cores (enforcement stub)\n",
			limits.MemoryBytes, limits.CPUCores)
	}
	return nil
}
