//go:build !linux

package runtime

import (
	"fmt"
	"os/exec"

	"github.com/vamsiv/aegisbox/pkg/image"
)

func applyResourceLimits(cmd *exec.Cmd, limits image.ResourceLimits) error {
	fmt.Printf("[aegisbox] resource limits (memory=%dB cpu=%.1f) require Linux cgroups v2 — skipped on this platform\n",
		limits.MemoryBytes, limits.CPUCores)
	return nil
}
