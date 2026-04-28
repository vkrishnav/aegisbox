package safety

import "fmt"

// Action determines what the sidecar does with matched output.
type Action int

const (
	ActionAllow  Action = iota
	ActionRedact        // replace matched bytes with [REDACTED]
	ActionBlock         // suppress entire output line
)

// Result is returned by a Classifier for a single output line.
type Result struct {
	Action     Action
	Classifier string
	Reason     string
	Matched    []byte
}

// Classifier inspects one line of model token output.
type Classifier interface {
	Name() string
	Classify(line []byte) Result
}

// Chain runs classifiers in sequence; first non-Allow result wins.
type Chain struct {
	classifiers []Classifier
}

func NewChain(classifiers []Classifier) *Chain {
	return &Chain{classifiers: classifiers}
}

func (c *Chain) Classify(line []byte) Result {
	for _, cl := range c.classifiers {
		if r := cl.Classify(line); r.Action != ActionAllow {
			return r
		}
	}
	return Result{Action: ActionAllow}
}

// BuildChain creates a Chain from classifier spec strings.
// Supported specs: "builtin:pii", "builtin:injection", "builtin:content-policy",
// "wasm:<path>".
func BuildChain(specs []string) (*Chain, error) {
	classifiers := make([]Classifier, 0, len(specs))
	for _, spec := range specs {
		cl, err := resolveClassifier(spec)
		if err != nil {
			return nil, fmt.Errorf("building chain: %w", err)
		}
		classifiers = append(classifiers, cl)
	}
	return NewChain(classifiers), nil
}
