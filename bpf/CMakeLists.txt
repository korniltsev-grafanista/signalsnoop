cmake_minimum_required(VERSION 3.16)
project(signalsnoop_bpf C)

set(CMAKE_C_COMPILER clang)
set(CMAKE_C_FLAGS "-target bpf -D__TARGET_ARCH_x86 -D__BPF_TRACING__ -O2 -g -Wall -Werror")

include_directories(headers)

# This is just for IDE support, not actual building
add_library(signalsnoop_bpf OBJECT signalsnoop.c)
