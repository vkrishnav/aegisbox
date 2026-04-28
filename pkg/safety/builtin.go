package safety

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// PIIClassifier redacts common PII patterns (SSN, email, credit card).
type PIIClassifier struct {
	patterns []*regexp.Regexp
}

func NewPIIClassifier() *PIIClassifier {
	return &PIIClassifier{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),                                       // SSN
			regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),       // email
			regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b`),             // Visa/MC
			regexp.MustCompile(`\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b`),         // phone
		},
	}
}

func (p *PIIClassifier) Name() string { return "builtin:pii" }

func (p *PIIClassifier) Classify(line []byte) Result {
	for _, re := range p.patterns {
		if m := re.Find(line); m != nil {
			return Result{Action: ActionRedact, Classifier: p.Name(), Reason: "PII detected", Matched: m}
		}
	}
	return Result{Action: ActionAllow}
}

// InjectionClassifier blocks lines containing prompt-injection heuristics.
type InjectionClassifier struct {
	triggers []string
}

func NewInjectionClassifier() *InjectionClassifier {
	return &InjectionClassifier{
		triggers: []string{
			"ignore previous instructions",
			"disregard your system prompt",
			"forget everything",
			"new instructions:",
			"[system]",
			"<|im_start|>",
			"</s><s>",
		},
	}
}

func (ic *InjectionClassifier) Name() string { return "builtin:injection" }

func (ic *InjectionClassifier) Classify(line []byte) Result {
	lower := bytes.ToLower(line)
	for _, trigger := range ic.triggers {
		if bytes.Contains(lower, []byte(strings.ToLower(trigger))) {
			return Result{
				Action:     ActionBlock,
				Classifier: ic.Name(),
				Reason:     "prompt injection pattern: " + trigger,
				Matched:    line,
			}
		}
	}
	return Result{Action: ActionAllow}
}

// ContentPolicyClassifier blocks output matching a configurable term blocklist.
type ContentPolicyClassifier struct {
	blocklist []string
}

func NewContentPolicyClassifier(blocklist []string) *ContentPolicyClassifier {
	return &ContentPolicyClassifier{blocklist: blocklist}
}

func (cp *ContentPolicyClassifier) Name() string { return "builtin:content-policy" }

func (cp *ContentPolicyClassifier) Classify(line []byte) Result {
	lower := bytes.ToLower(line)
	for _, term := range cp.blocklist {
		if bytes.Contains(lower, []byte(strings.ToLower(term))) {
			return Result{
				Action:     ActionBlock,
				Classifier: cp.Name(),
				Reason:     "content policy violation: " + term,
				Matched:    line,
			}
		}
	}
	return Result{Action: ActionAllow}
}

// resolveClassifier maps a spec string to a Classifier implementation.
func resolveClassifier(spec string) (Classifier, error) {
	switch {
	case spec == "builtin:pii":
		return NewPIIClassifier(), nil
	case spec == "builtin:injection":
		return NewInjectionClassifier(), nil
	case spec == "builtin:content-policy":
		return NewContentPolicyClassifier(nil), nil
	case strings.HasPrefix(spec, "wasm:"):
		return LoadWASMClassifier(strings.TrimPrefix(spec, "wasm:"))
	default:
		return nil, fmt.Errorf("unknown classifier: %q", spec)
	}
}
