FROM ghcr.io/cilium/ebpf-builder:1694533004 as builder
WORKDIR /prism
COPY . .

RUN make build

FROM ubuntu:22.04
ARG DIR_NAME
WORKDIR /
RUN mkdir web

COPY --from=builder /prism/web /web
COPY --from=builder /prism/prism .
RUN chmod +x prism