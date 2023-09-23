#pragma once


// #) Definition for Kprobes

// Data buffer message size. BPF can submit at most this amount of data to a perf buffer.
// Kernel size limit is 32KiB. See https://github.com/iovisor/bcc/issues/2519 for more details.
// But here we took ~16Kib & not 32Kib because the overall size of the `struct socket_data_event_t` becomes more than 32Kib.
// And this size should be in the power of 2 only.
#define MAX_MSG_SIZE 16383 // (16KB-1) or (2^14-1 bytes)


// This defines how many chunks a ringbuf can support. This applies to messages that are over MAX_MSG_SIZE,
// and effectively makes the maximum message size to be CHUNK_LIMIT*MAX_MSG_SIZE.
#define CHUNK_LIMIT 50



// #) Enums
enum traffic_direction_t
{
    kEgress,
    kIngress,
};

// #) Structs

//--- Ingress structs ---

// A struct representing a unique ID that is composed of the pid, the file
// descriptor and the creation time of the struct.
struct conn_id_t
{
    // Process ID
    u32 pid;
    // The file descriptor to the opened network connection.
    s32 fd;
    // Timestamp at the initialization of the struct.
    u64 tsid;
};

// This struct contains information collected when a connection is established,
// via an accept4() syscall.
struct conn_info_t
{
    // Connection identifier.
    struct conn_id_t conn_id;

    // The number of bytes written/read on this connection.
    s64 wr_bytes;
    s64 rd_bytes;

    // A flag indicating we identified the connection as HTTP.
    bool is_http;
};

// An helper struct that hold the addr argument of the syscall.
struct accept_args_t
{
    struct sockaddr_in *addr;
};

// An helper struct to cache input argument of read/write syscalls between the
// entry hook and the exit hook.
struct data_args_t
{
    s32 fd;
    char *buf;
    struct iovec *iovec;
};

// An helper struct that hold the input arguments of the close syscall.
struct close_args_t
{
    s32 fd;
};

// A struct describing the event that we send to the user mode upon a new connection.
struct socket_open_event_t
{
    // The time of the event.
    u64 timestamp_ns;
    // A unique ID for the connection.
    struct conn_id_t conn_id;
    // The address of the client.
    struct sockaddr_in addr;
};

// Struct describing the close event being sent to the user mode.
struct socket_close_event_t
{
    // Timestamp of the close syscall
    u64 timestamp_ns;
    // The unique ID of the connection
    struct conn_id_t conn_id;
    // Total number of bytes written on that connection
    s64 wr_bytes;
    // Total number of bytes read on that connection
    s64 rd_bytes;
};

// Struct describing the data event being sent to the user mode.
struct socket_data_event_t
{

    // The timestamp when syscall completed (return probe was triggered).
    u64 timestamp_ns;

    // Connection identifier (PID, FD, etc.).
    struct conn_id_t conn_id;

    // The type of the actual data that the msg field encodes, which is used by the caller
    // to determine how to interpret the data.
    enum traffic_direction_t direction;

    // The size of the original message. We use this to truncate msg field to minimize the amount
    // of data being transferred.
    u32 msg_size;

    // A 0-based position number for this event on the connection, in terms of byte position.
    // The position is for the first byte of this message.
    u64 pos;

    // Actual buffer
    char msg[MAX_MSG_SIZE];

    //To verify the request data
    s64 validate_rd_bytes;

    //To verify the response data
    s64 validate_wr_bytes;
};