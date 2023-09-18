# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
DEV ?= lo
HOST ?= 10.2.0.105

STOREHOUSE ?= zmosquito
NAME ?= prism
VERSION ?= v0.0.1
IMAGE ?= $(STOREHOUSE)/$(NAME):$(VERSION)

format:
	find . -type f -name "*.c" | xargs clang-format -i

env:
	go env -w GOPROXY=https://goproxy.cn,direct && go install github.com/cilium/ebpf/cmd/bpf2go@latest

# $BPF_CLANG is used in go:generate invocations.
gen: export BPF_CLANG := $(CLANG)
gen: export BPF_CFLAGS := $(CFLAGS)
gen: export GO111MODULE=on
gen:
	go generate ./...

ps:
	ssh root@$(HOST) "rm -rf /root/prism && mkdir prism"
	scp -r * root@$(HOST):/root/prism/

pl:
	scp -r root@$(HOST):/root/prism/* .

build: env gen
	go mod tidy && go build -ldflags "-s -w" -o prism .

run: build
	./prism -n $(DEV)

build-image:
	docker build -t $(IMAGE) .

run-image:
	docker run --net host --privileged --name $(NAME) -itd $(IMAGE) ./$(NAME) -n $(DEV)