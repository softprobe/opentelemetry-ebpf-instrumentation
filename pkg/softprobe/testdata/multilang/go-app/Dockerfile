FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

WORKDIR /src
COPY go.mod /src/go.mod
COPY main.go /src/main.go
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /out/multilang-go .

FROM debian:bookworm-slim
COPY --from=builder /out/multilang-go /usr/local/bin/multilang-go
EXPOSE 8083
ENTRYPOINT ["/usr/local/bin/multilang-go"]
