FROM golang:1.22-alpine AS builder

WORKDIR /prj

COPY go.mod go.sum ./

RUN go mod download

COPY cmd/ cmd/

COPY internal/ internal/

COPY pkg/ pkg/
COPY docs/ docs/

COPY .env ./

RUN go build -o ./prj_main ./cmd/auth_server/main.go

FROM alpine:latest

COPY --from=builder prj/prj_main /bin/prj_main

CMD ["/bin/prj_main"]
