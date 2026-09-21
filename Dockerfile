FROM golang:1.26-alpine3.24@sha256:51a7c389a5ddaf82f527191a1e9bff9928655130a44e4975dd1d7e0acf59f1ae AS builder
RUN apk add --no-cache gcc musl-dev git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
# Keep LDFLAGS version (release.yml `make cross` drops it — fixed there too).
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo '0.1.0-dev')" \
  -o /trace ./cmd/trace

FROM alpine:3.21.8@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507
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
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz | grep -q ok || exit 1
ENTRYPOINT ["trace"]
CMD ["server", "--http-addr", ":8080"]
