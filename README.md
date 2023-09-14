# Prism

Prism is an eBPF-Based interface generator that captures the HTTP traffic of Ingress and Egress through TC and passes it to the user mode through ringbuf to assemble complete data.

# Run

- Kernel >= 5.8.0

## operating run

> device_name, replace with the name of the network device the program is attached to (e.g. eth0)

```bash
prism -n <device_name>
```

## docker run

```bash
docker run --net host --privileged --name prism -itd zmosquito/prism:v0.0.1 ./prism -n <device_name>
```

# How to compile

## require

- Kernel >= 5.8.0 
- LLvm >= 14
- Clang >= 14
- Golang >= 1.18
- Cmake

```bash
# Ubuntu 22.04
apt-get install linux-kernel-headers linux-headers-$(uname -r)
apt-get update && apt-get install -y make clang-14 llvm-14 libc6-dev libc6-dev-i386 libz-dev libelf-dev libbpf-dev iproute2 && apt-get clean
ln -s $(which clang-14) /usr/bin/clang && ln -s $(which llc-14) /usr/bin/llc
```

## compile

```bash
make build
```

## docker

compile by docker

```bash
docker run --rm  -v /root/prism:/root/prism ghcr.io/cilium/ebpf-builder:1694533004 bash -c "cd /root/prism && make build"
```

## Demo
<iframe src="//player.bilibili.com/player.html?aid=873470777&bvid=BV1tK4y1c7rh&cid=1266597417&p=1" scrolling="no" border="0" frameborder="no" framespacing="0" allowfullscreen="true"> </iframe>
