# Prism

eBPF-based Interface Builder

# How to compile

## require

- kernel >= 5.8.0 
- LLvm >= 11
- Clang >= 11
- Golang >= 1.18
- cmake

```bash
# Ubuntu 22.04
apt-get install linux-kernel-headers linux-headers-$(uname -r)
apt-get update && apt-get install -y make clang-11 llvm-11 libc6-dev libc6-dev-i386 libz-dev libelf-dev libbpf-dev iproute2 && apt-get clean
ln -s $(which clang-11) /usr/bin/clang && ln -s $(which llc-11) /usr/bin/llc
```

## compile

```bash
make gen
```

# Run

```bash
export GO111MODULE=on && go run -exec sudo main.go bpf_bpfel.go parse_http.go save.go web.go -n <device_name>
```

> device_name 替换为程序附加到的网络设备的名称（例如 eth0）

# Docker run

```bash

```

