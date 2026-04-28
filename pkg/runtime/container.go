package runtime

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/vamsiv/aegisbox/pkg/image"
	"github.com/vamsiv/aegisbox/pkg/safety"
)

// Container wraps a running model process with its safety sidecar.
type Container struct {
	id      string
	img     *image.Image
	cmd     *exec.Cmd
	sidecar *Sidecar
}

var (
	mu         sync.Mutex
	containers = map[string]*Container{}
)

// NewContainer prepares a container from an ABX image.
// cfgFile overrides safety/resource config (reserved for future YAML loading).
func NewContainer(img *image.Image, _ string) (*Container, error) {
	if len(img.Manifest.Entrypoint) == 0 {
		return nil, fmt.Errorf("image has no entrypoint")
	}

	ep := img.Manifest.Entrypoint
	cmd := exec.Command(ep[0], ep[1:]...)

	if err := applyResourceLimits(cmd, img.Manifest.Resources); err != nil {
		return nil, fmt.Errorf("applying resource limits: %w", err)
	}

	chain, err := safety.BuildChain(img.Manifest.Safety.Classifiers)
	if err != nil {
		return nil, fmt.Errorf("building classifier chain: %w", err)
	}

	sidecar := NewSidecar(chain)
	cmd.Stdout = sidecar
	cmd.Stderr = sidecar.Stderr()

	c := &Container{id: generateID(), img: img, cmd: cmd, sidecar: sidecar}

	mu.Lock()
	containers[c.id] = c
	mu.Unlock()

	return c, nil
}

// Run starts the model process and blocks until it exits.
func (c *Container) Run() error {
	defer func() {
		mu.Lock()
		delete(containers, c.id)
		mu.Unlock()
	}()

	c.sidecar.Start()
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("starting model process: %w", err)
	}
	err := c.cmd.Wait()
	c.sidecar.Close()
	return err
}

// ListContainers writes a tabular list of running containers to w.
func ListContainers(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tMODEL\tSTATUS")
	for _, c := range containers {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.id[:8], c.img.Manifest.ModelID, "running")
	}
	tw.Flush()
}

func generateID() string {
	return fmt.Sprintf("%016x", time.Now().UnixNano())
}
