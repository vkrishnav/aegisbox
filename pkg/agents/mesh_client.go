package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultMeshURL = "http://localhost:8080"

// Task mirrors the agent-protocol Task type.
type Task struct {
	TaskID    string `json:"task_id"`
	Input     string `json:"input"`
	CreatedAt string `json:"created_at"`
}

// StepResult mirrors the agent-protocol Step output.
type StepResult struct {
	StepID string `json:"step_id"`
	Output string `json:"output"`
	IsLast bool   `json:"is_last"`
}

// MeshClient routes queries through an agent-protocol HTTP adapter.
// AegisBox uses this to let a contained model participate in the agent mesh
// before its output passes through the safety sidecar.
type MeshClient struct {
	baseURL string
	http    *http.Client
}

func NewMeshClient(baseURL string) *MeshClient {
	if baseURL == "" {
		baseURL = defaultMeshURL
	}
	return &MeshClient{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// CreateTask creates a new task on the mesh agent.
func (m *MeshClient) CreateTask(ctx context.Context, input string) (*Task, error) {
	body, _ := json.Marshal(map[string]string{"input": input})
	resp, err := m.post(ctx, "/ap/v1/agent/tasks", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var task Task
	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		return nil, fmt.Errorf("decoding task: %w", err)
	}
	return &task, nil
}

// ExecuteStep runs the next step on an existing task.
func (m *MeshClient) ExecuteStep(ctx context.Context, taskID, input string) (*StepResult, error) {
	body, _ := json.Marshal(map[string]string{"input": input})
	resp, err := m.post(ctx, fmt.Sprintf("/ap/v1/agent/tasks/%s/steps", taskID), body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var step StepResult
	if err := json.NewDecoder(resp.Body).Decode(&step); err != nil {
		return nil, fmt.Errorf("decoding step: %w", err)
	}
	return &step, nil
}

func (m *MeshClient) post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mesh request to %s: %w", path, err)
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("mesh %s: %s", path, b)
	}
	return resp, nil
}
