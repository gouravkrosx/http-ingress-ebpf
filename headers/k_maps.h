#pragma once

// #) Maps

// It contains the pid of the application.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} app_pid_map SEC(".maps");


//--- Ingress maps ---

// A map of the active connections. The name of the map is conn_info_map
// the key is of type uint64_t, the value is of type struct conn_info_t,
// and the map won't be bigger than 128KB.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct conn_info_t);
    __uint(max_entries, 131072);
} conn_info_map SEC(".maps");

// An helper map that will help us cache the input arguments of the accept syscall
// between the entry hook and the return hook.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct accept_args_t);
    __uint(max_entries, 1024);
} active_accept_args_map SEC(".maps");

// Helper map to store write syscall arguments between entry and exit hooks.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct data_args_t);
    __uint(max_entries, 1024);
} active_write_args_map SEC(".maps");

// Helper map to store read syscall arguments between entry and exit hooks.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct data_args_t);
    __uint(max_entries, 1024);
} active_read_args_map SEC(".maps");

// An helper map to store close syscall arguments between entry and exit syscalls.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct close_args_t);
    __uint(max_entries, 1024);
} active_close_args_map SEC(".maps");

// A perf buffer that allows us send events from kernel to user mode.
// This perf buffer is dedicated for special type of events - open events.
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_open_events SEC(".maps");

// Perf buffer to send to the user-mode the close events
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_close_events SEC(".maps");

// Ring buffer to send to the user-mode the data events.
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26); //  64 MB
} socket_data_events SEC(".maps");

// We can't allocate more than 512 bytes of data on the btf stack, hence we used PERCPU_ARRAY which gives 32Kb of data from the heap
//  in order to send the buffer of requests and responses.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct socket_data_event_t);
    __uint(max_entries, 1);
} socket_data_event_buffer_heap SEC(".maps");
