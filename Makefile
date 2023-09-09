# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
DEV ?= lo

NAME ?= prism
VERSION ?= v0.0.1
IMAGE ?= $(NAME):$(VERSION)

format:
	find . -type f -name "*.c" | xargs clang-format -i

# $BPF_CLANG is used in go:generate invocations.
gen: export BPF_CLANG := $(CLANG)
gen: export BPF_CFLAGS := $(CFLAGS)
gen: export GO111MODULE=on
gen:
	go generate ./...

ps:
	ssh root@10.2.0.105 "rm -rf /root/prism/*.*"
	scp -r * root@10.2.0.105:/root/prism/

pl:
	scp -r root@10.2.0.105:/root/prism/* .

test-run:
	export GO111MODULE=on && go run -exec sudo main.go ringbuf_bpfel.go perf_bpfel.go parse_http.go save.go web.go utils.go -n $(DEV)

build:
	docker build -t $(IMAGE) .

run:
	docker run --net host --privileged --name $(NAME) -itd $(IMAGE) ./$(NAME) -n $(DEV)