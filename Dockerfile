FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -trimpath -o /app/so-token-fetcher ./main.go

FROM alpine:3.20.3

USER 1001
WORKDIR /app

COPY --from=builder /app/so-token-fetcher .

CMD ["/app/so-token-fetcher"]