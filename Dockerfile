FROM golang:latest AS builder

WORKDIR /app

COPY go.mod ./

RUN go mod download

COPY . .

RUN go build -o user-service .

FROM debian:unstable-slim

WORKDIR /app

COPY --from=builder /app/user-service .
COPY --from=builder /app/logs ./logs
COPY --from=builder /app/migrations ./migrations

RUN touch .env

EXPOSE 50031

CMD ["./user-service"]