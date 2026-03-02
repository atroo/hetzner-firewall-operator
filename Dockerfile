FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /operator ./cmd/operator

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /operator /operator
USER 65532:65532
ENTRYPOINT ["/operator"]
