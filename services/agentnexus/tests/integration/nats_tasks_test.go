package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
)

func TestNATSTaskEventDelivery(t *testing.T) {
	url := os.Getenv("AGENTNEXUS_TEST_NATS_URL")
	if url == "" {
		t.Skip("AGENTNEXUS_TEST_NATS_URL is not set")
	}

	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("create jetstream context: %v", err)
	}

	streamName := fmt.Sprintf("AGENTNEXUS_TASKS_TEST_%d", time.Now().UnixNano())
	if _, err := js.AddStream(&nats.StreamConfig{
		Name:     streamName,
		Subjects: []string{"agentnexus.tasks.*"},
	}); err != nil {
		t.Fatalf("add stream: %v", err)
	}
	defer js.DeleteStream(streamName)

	sub, err := js.PullSubscribe(tasks.SubjectTaskCreated, "worker", nats.BindStream(streamName))
	if err != nil {
		t.Fatalf("pull subscribe: %v", err)
	}

	publisher, err := tasks.NewNATSPublisher(nc)
	if err != nil {
		t.Fatalf("NewNATSPublisher returned error: %v", err)
	}

	event := tasks.TaskEvent{
		Subject:      tasks.SubjectTaskCreated,
		EnterpriseID: "ent_1",
		TaskRunID:    "task_1",
		Status:       tasks.TaskStatusQueued,
	}
	if err := publisher.PublishTaskEvent(context.Background(), event); err != nil {
		t.Fatalf("PublishTaskEvent returned error: %v", err)
	}

	msgs, err := sub.Fetch(1, nats.MaxWait(5*time.Second))
	if err != nil {
		t.Fatalf("fetch message: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("len(msgs) = %d, want 1", len(msgs))
	}
	defer msgs[0].Ack()

	var got tasks.TaskEvent
	if err := json.Unmarshal(msgs[0].Data, &got); err != nil {
		t.Fatalf("decode task event: %v", err)
	}
	if got.TaskRunID != "task_1" || got.Subject != tasks.SubjectTaskCreated {
		t.Fatalf("event = %+v, want task_1 created", got)
	}
}
