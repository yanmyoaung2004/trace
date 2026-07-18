package taskqueue

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/innoigniter/edge/internal/db"
)

type Task struct {
	ID               string
	InvestigationID  string
	Agent            string
	Action           string
	Payload          map[string]any
	Status           string
	Result           map[string]any
	Error            string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Queue struct {
	db *db.DB
}

func New(database *db.DB) *Queue {
	return &Queue{db: database}
}

func (q *Queue) Enqueue(ctx context.Context, investigationID, agent, action string, payload map[string]any) (*Task, error) {
	id := uuid.New().String()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	_, err = q.db.ExecContext(ctx,
		`INSERT INTO tasks (id, investigation_id, agent, action, payload, status)
		 VALUES (?, ?, ?, ?, ?, 'pending')`,
		id, investigationID, agent, action, string(payloadJSON))
	if err != nil {
		return nil, fmt.Errorf("insert task: %w", err)
	}

	return &Task{ID: id, InvestigationID: investigationID, Agent: agent, Action: action, Status: "pending"}, nil
}

func (q *Queue) Claim(ctx context.Context) (*Task, error) {
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var (
		id, invID, agent, action, payloadStr, status string
		createdAt, updatedAt                         string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, investigation_id, agent, action, payload, status, created_at, updated_at
		 FROM tasks WHERE status = 'pending' ORDER BY created_at LIMIT 1`).
		Scan(&id, &invID, &agent, &action, &payloadStr, &status, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim task: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE tasks SET status = 'running', updated_at = datetime('now') WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("update task status: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	var payload map[string]any
	json.Unmarshal([]byte(payloadStr), &payload)

	task := &Task{
		ID:              id,
		InvestigationID: invID,
		Agent:           agent,
		Action:          action,
		Payload:         payload,
		Status:          "running",
	}
	return task, nil
}

func (q *Queue) Complete(ctx context.Context, taskID string, result map[string]any) error {
	resultJSON, _ := json.Marshal(result)
	_, err := q.db.ExecContext(ctx,
		`UPDATE tasks SET status = 'done', result = ?, updated_at = datetime('now') WHERE id = ?`,
		string(resultJSON), taskID)
	return err
}

func (q *Queue) Fail(ctx context.Context, taskID string, errMsg string) error {
	_, err := q.db.ExecContext(ctx,
		`UPDATE tasks SET status = 'failed', error = ?, updated_at = datetime('now') WHERE id = ?`,
		errMsg, taskID)
	return err
}
