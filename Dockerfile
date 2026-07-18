FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo '0.1.0-dev')" \
  -o /trace ./cmd/trace

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -h /home/trace trace
WORKDIR /home/trace
COPY --from=builder /trace /usr/local/bin/
COPY --from=builder /src/playbooks /home/trace/.trace/playbooks/
COPY --from=builder /src/intel /home/trace/.trace/intel/
RUN mkdir -p /home/trace/.trace/data /home/trace/.trace/logs
RUN chown -R trace:trace /home/trace/.trace
USER trace
EXPOSE 8080
ENTRYPOINT ["trace"]
CMD ["server", "--http-addr", ":8080"]
