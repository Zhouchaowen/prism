FROM ebpf-build:v22.04-llvm-14 as builder
WORKDIR /prism
COPY . .

RUN make gen

FROM golang:1.18.6 as compiler
WORKDIR /app
COPY --from=builder /prism .

RUN go env -w GO111MODULE=on && go env -w GOPROXY=https://goproxy.cn,direct && go mod tidy
RUN go build -ldflags "-s -w" -o prism .

FROM ubuntu:22.04
ARG DIR_NAME
WORKDIR /
RUN mkdir web

COPY --from=builder /prism/web /web
COPY --from=compiler /app/prism .
RUN chmod +x prism