package safety

import (
	"context"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// WASMClassifier loads a .wasm plugin that implements the classifier ABI:
//
//	export function classify(ptr i32, len i32) i32
//
// Return values map to Action constants: 0=Allow, 1=Redact, 2=Block.
type WASMClassifier struct {
	name    string
	rt      wazero.Runtime
	mod     api.Module
	fn      api.Function
	ctx     context.Context
	cancel  context.CancelFunc
}

// LoadWASMClassifier compiles and instantiates a WASM classifier plugin.
func LoadWASMClassifier(path string) (*WASMClassifier, error) {
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading wasm plugin %s: %w", path, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rt := wazero.NewRuntime(ctx)

	mod, err := rt.Instantiate(ctx, wasmBytes)
	if err != nil {
		cancel()
		rt.Close(context.Background())
		return nil, fmt.Errorf("instantiating wasm module %s: %w", path, err)
	}

	fn := mod.ExportedFunction("classify")
	if fn == nil {
		cancel()
		rt.Close(context.Background())
		return nil, fmt.Errorf("wasm plugin %s must export 'classify(ptr i32, len i32) i32'", path)
	}

	return &WASMClassifier{
		name:   "wasm:" + path,
		rt:     rt,
		mod:    mod,
		fn:     fn,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (w *WASMClassifier) Name() string { return w.name }

// Close releases the WASM runtime. Call when the container stops.
func (w *WASMClassifier) Close() {
	w.cancel()
	w.rt.Close(context.Background())
}

func (w *WASMClassifier) Classify(line []byte) Result {
	mem := w.mod.Memory()
	if mem == nil || len(line) == 0 {
		return Result{Action: ActionAllow}
	}

	// Write input at offset 0 (simplified — production would use a malloc export).
	const offset uint32 = 0
	if !mem.Write(offset, line) {
		return Result{Action: ActionAllow}
	}

	results, err := w.fn.Call(w.ctx, uint64(offset), uint64(len(line)))
	if err != nil || len(results) == 0 {
		return Result{Action: ActionAllow}
	}

	switch Action(results[0]) {
	case ActionBlock:
		return Result{Action: ActionBlock, Classifier: w.name, Reason: "wasm plugin blocked"}
	case ActionRedact:
		return Result{Action: ActionRedact, Classifier: w.name, Reason: "wasm plugin redacted", Matched: line}
	default:
		return Result{Action: ActionAllow}
	}
}
