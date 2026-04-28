# AegisBox

Purpose-built container runtime for deploying LLMs safely. Designed around four safety pillars:

1. **Resource isolation** — Linux namespaces + cgroups v2 (CPU, memory, GPU limits)
2. **Output filtering** — Safety Sidecar intercepts every output token through a WASM-extensible classifier chain
3. **Reproducible deployments** — Content-addressed ABX image format (BLAKE3-hashed, Sigstore-signed, SBOM-attested)
4. **Network/syscall restrictions** — Allowlist-based proxy + eBPF probe stubs

Compliance targets: EU AI Act, NIST AI RMF.

---

## Quick start

```bash
make build

# Build an image from a model directory
./bin/aegisbox build ./my-model --tag llama3:v1.0

# Inspect the image manifest and SBOM
./bin/aegisbox inspect ./llama3-v1.0.abx

# Run it
./bin/aegisbox run ./llama3-v1.0.abx

# List running containers
./bin/aegisbox ps
```

Python CLI (requires `pip install -r cli/requirements.txt`):

```bash
python cli/aegisbox.py build ./my-model --tag llama3:v1.0
python cli/aegisbox.py ps
```

---

## ABX image format

An `.abx` file is a tar archive containing:

| Entry | Description |
|---|---|
| `manifest.json` | Typed manifest: modelId, BLAKE3 hash, SBOM, resource limits, safety config, entrypoint |
| `model/**` | Model weights and serving code |

The BLAKE3 hash covers all `model/` content (excluding the manifest itself), enabling tamper detection on load.

## Safety Sidecar

Every model process gets a Safety Sidecar that:

1. Intercepts all stdout token output via an `io.Pipe`
2. Feeds each line through a **classifier chain** (first non-Allow result wins)
3. Either forwards, redacts (`[REDACTED]`), or blocks output accordingly

Built-in classifiers:

| Spec | Behaviour |
|---|---|
| `builtin:pii` | Regex-based redaction of SSN, email, credit card, phone |
| `builtin:injection` | Keyword heuristics for prompt-injection patterns |
| `builtin:content-policy` | Configurable term blocklist |
| `wasm:<path>` | WASM plugin (export `classify(ptr i32, len i32) i32`) |

## Network policy

Three modes: `restricted` (allowlist), `isolated` (deny all), `open`.

The `Enforcer` implements an HTTP CONNECT proxy. Set `HTTP_PROXY` / `HTTPS_PROXY`
in the container environment to route outbound traffic through it.

## Agent-protocol integration

`pkg/agents.MeshClient` lets AegisBox act as a secure execution node in an
agent mesh. When running a model, route queries through the mesh adapter
(`../agent-protocol`) before passing them to the contained model — output still
flows through the safety sidecar on the way back.

```go
client := agents.NewMeshClient("http://mesh-gateway:8080")
task, _ := client.CreateTask(ctx, userPrompt)
step, _ := client.ExecuteStep(ctx, task.TaskID, "")
```

---

## Project layout

```
aegisbox/
├── main.go                  CLI entry (cobra: run, build, inspect, ps)
├── config/aegisbox.yaml     Example runtime config
├── pkg/
│   ├── image/               ABX image format (manifest, builder, loader)
│   ├── runtime/             Container execution + Safety Sidecar
│   ├── safety/              Classifier chain + built-in + WASM plugins
│   ├── network/             Policy model + HTTP CONNECT enforcer
│   └── agents/              agent-protocol mesh client
└── cli/
    └── aegisbox.py          Rich Python CLI wrapper
```

## Implementation status

| Component | Status |
|---|---|
| ABX image build + load | Implemented |
| BLAKE3 hash verification | Implemented |
| Safety Sidecar (pipe + scanner) | Implemented |
| Built-in classifiers (PII, injection, content policy) | Implemented |
| WASM classifier plugins (wazero) | Stub — ABI defined, runtime wired |
| Network policy model | Implemented |
| HTTP CONNECT proxy enforcer | Implemented |
| Linux namespace isolation | Implemented (requires root) |
| cgroups v2 resource limits | Stub — interface present, write path TBD |
| eBPF probe manager | Not yet implemented |
| Sigstore signature verification | Not yet implemented |
