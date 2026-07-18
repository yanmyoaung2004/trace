FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")" \
  -o /innoigniter ./cmd/innoigniter

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -h /home/innoigniter innoigniter
WORKDIR /home/innoigniter
COPY --from=builder /innoigniter /usr/local/bin/
COPY --from=builder /src/playbooks /home/innoigniter/.innoigniter/playbooks/
COPY --from=builder /src/intel /home/innoigniter/.innoigniter/intel/
RUN mkdir -p /home/innoigniter/.innoigniter/data /home/innoigniter/.innoigniter/logs
RUN chown -R innoigniter:innoigniter /home/innoigniter/.innoigniter
USER innoigniter
EXPOSE 8080
ENTRYPOINT ["innoigniter"]
CMD ["server", "--http-addr", ":8080"]
