FROM golang:1.18.6 as compiler
WORKDIR /app

COPY . .

RUN go env -w GO111MODULE=on && go env -w GOPROXY=https://goproxy.cn,direct && go mod tidy

RUN go build -ldflags "-s -w" -o prism .

FROM ubuntu:22.04
ARG DIR_NAME
WORKDIR /

COPY --from=compiler /app/prism .
RUN chmod +x prism