# gRPC Sidecar Plugin Architecture

For platforms where Go's `plugin` package is unavailable (Windows) or when plugins should be written in other languages (Python, Rust, etc.), use the gRPC sidecar pattern.

## Architecture

```
┌─────────────────┐     gRPC     ┌──────────────────┐
│   Trace Core     │◄───────────►│  Plugin Process   │
│                  │             │  (sidecar)        │
│  Plugin Loader   │             │                   │
│  gRPC Client     │             │  gRPC Server      │
└─────────────────┘             └──────────────────┘
```

## Proto Definition

Save as `proto/agent.proto`:

```protobuf
syntax = "proto3";
package trace.plugin;

service Agent {
  rpc Name(Empty) returns (NameResponse);
  rpc Capabilities(Empty) returns (CapabilitiesResponse);
  rpc Execute(ExecuteRequest) returns (ExecuteResponse);
}

message Empty {}

message NameResponse {
  string name = 1;
}

message Capability {
  string action = 1;
  repeated string inputs = 2;
  repeated string outputs = 3;
}

message CapabilitiesResponse {
  repeated Capability capabilities = 1;
}

message ExecuteRequest {
  string action = 1;
  map<string, string> params = 2;
}

message ExecuteResponse {
  map<string, string> output = 1;
  string error = 2;
}
```

## Go Client (Trace Core)

```go
package plugin

import (
    "context"
    "fmt"
    "os/exec"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "trace/proto"
)

type GRPCAgent struct {
    client pb.AgentClient
    cancel context.CancelFunc
    cmd    *exec.Cmd
}

func NewGRPCAgent(socketPath string) (*GRPCAgent, error) {
    conn, err := grpc.Dial(socketPath,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(10*1024*1024)),
    )
    if err != nil {
        return nil, fmt.Errorf("grpc dial: %w", err)
    }
    return &GRPCAgent{client: pb.NewAgentClient(conn)}, nil
}
```

## Python Plugin (Example)

```python
import grpc
from concurrent import futures
import agent_pb2
import agent_pb2_grpc

class SiftPlugin(agent_pb2_grpc.AgentServicer):
    def Name(self, request, context):
        return agent_pb2.NameResponse(name="custom-sift")

    def Capabilities(self, request, context):
        return agent_pb2.CapabilitiesResponse(
            capabilities=[agent_pb2.Capability(
                action="yara_scan",
                inputs=["path"],
                outputs=["matches", "count"]
            )]
        )

    def Execute(self, request, context):
        if request.action == "yara_scan":
            return self.yara_scan(request.params)
        return agent_pb2.ExecuteResponse(error="unknown action")

server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
agent_pb2_grpc.add_AgentServicer_to_server(SiftPlugin(), server)
server.add_insecure_port("unix:///tmp/trace-plugin.sock")
server.start()
server.wait_for_termination()
```

## Lifecycle

1. Trace loads a plugin manifest (`.json`) describing the sidecar command + socket
2. Trace starts the sidecar process, waits for it to bind
3. Trace connects via gRPC and queries Name/Capabilities
4. On shutdown, Trace sends SIGTERM to the sidecar
5. Plugin hot-reload: stop sidecar → start new sidecar
