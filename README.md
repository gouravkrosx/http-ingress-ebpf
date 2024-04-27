# Http-Ingress-Ebpf

This utility helps you compile and run an eBPF program on Linux systems.

## Prerequisites

Before running this script, ensure that your system meets the following requirements:

- Kernel version 5.15 or higher
- Clang-14 installed

## Getting Started

Follow these steps to compile and run the eBPF program:

1. Make the script executable:
```bash
chmod +x run.sh
```
2. Run the script with the PID of the target application:
```bash
./run.sh <pid of the application>
```
Replace <pid of the application> with the actual process ID of the application you wish to target.