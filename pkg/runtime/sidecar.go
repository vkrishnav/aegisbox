package runtime

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/vamsiv/aegisbox/pkg/safety"
)

// Sidecar runs as PID 1's stdout interceptor, passing all model output through
// the classifier chain before forwarding to the host.
type Sidecar struct {
	chain *safety.Chain
	pr    *io.PipeReader
	pw    *io.PipeWriter
}

func NewSidecar(chain *safety.Chain) *Sidecar {
	pr, pw := io.Pipe()
	return &Sidecar{chain: chain, pr: pr, pw: pw}
}

// Write implements io.Writer — receives raw bytes from the model's stdout.
func (s *Sidecar) Write(p []byte) (int, error) {
	return s.pw.Write(p)
}

// Stderr returns the passthrough writer for the model's stderr.
func (s *Sidecar) Stderr() io.Writer { return os.Stderr }

// Start launches the background filter goroutine. Call before cmd.Start().
func (s *Sidecar) Start() {
	go s.filter()
}

// Close signals EOF to the filter goroutine. Call after cmd.Wait() returns.
func (s *Sidecar) Close() {
	s.pw.Close()
}

func (s *Sidecar) filter() {
	scanner := bufio.NewScanner(s.pr)
	for scanner.Scan() {
		line := scanner.Bytes()
		result := s.chain.Classify(line)
		switch result.Action {
		case safety.ActionBlock:
			fmt.Fprintf(os.Stderr, "[aegisbox:blocked] %s (classifier: %s)\n",
				result.Reason, result.Classifier)
		case safety.ActionRedact:
			redacted := bytes.ReplaceAll(line, result.Matched, []byte("[REDACTED]"))
			os.Stdout.Write(append(redacted, '\n'))
		default:
			os.Stdout.Write(append(line, '\n'))
		}
	}
}
