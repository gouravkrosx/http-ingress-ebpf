#! /bin/sh

# Check the machine architecture
ARCH=$(uname -m)

if [ "$ARCH" = "x86_64" ]; then
  # For amd64
  export BPF_CLANG=clang-14
  export BPF_CFLAGS="-I/usr/include/x86_64-linux-gnu -D__x86_64__ -O2 -g -Wall -Werror"
  export TARGET=amd64
elif [ "$ARCH" = "aarch64" ]; then
  # For arm64
  export BPF_CLANG=clang-14
  export BPF_CFLAGS="-I/usr/include/aarch64-linux-gnu -D__aarch64__ -O2 -g -Wall -Werror"
  export TARGET=arm64
else
  echo "Unsupported architecture: $ARCH"
  exit 1
fi

# Compile and run the ebpf program...
go generate ./... && go run -exec "sudo -E" ./ebpf --pid 61002
