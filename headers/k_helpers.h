#pragma once

// #) Helper Functions

// Generates a unique identifier using a tgid (Thread Global ID) and a fd (File Descriptor).
static __inline u64 gen_tgid_fd(u32 tgid, u32 sockfd)
{
    return ((u64)tgid << 32) | sockfd;
}

// An helper function that checks if the syscall finished successfully and if it did
// saves the new connection in a dedicated map of connections
static __inline void process_syscall_accept(struct pt_regs *ctx, u64 id, const struct accept_args_t *args)
{
    // Extracting the return code, and checking if it represent a failure,
    // if it does, we abort the as we have nothing to do.
    s32 ret_fd = PT_REGS_RC(ctx);
    if (ret_fd <= 0)
    {
        return;
    }
    bpf_printk("[process_syscall_accept]:Got a new connection on fd:%d", ret_fd);

    struct conn_info_t conn_info = {};
    u32 pid = id >> 32;
    conn_info.conn_id.pid = pid;
    conn_info.conn_id.fd = ret_fd;
    conn_info.conn_id.tsid = bpf_ktime_get_ns();

    u64 pid_fd = ((u64)pid << 32) | (u32)ret_fd;
    // Saving the connection info in a global map, so in the other syscalls
    // (read, write and close) we will be able to know that we have seen
    // the connection
    bpf_map_update_elem(&conn_info_map, &pid_fd, &conn_info, BPF_ANY);

    // Sending an open event to the user mode, to let the user mode know that we
    // have identified a new connection.
    struct socket_open_event_t open_event = {};
    open_event.timestamp_ns = bpf_ktime_get_ns();
    open_event.conn_id = conn_info.conn_id;
    bpf_probe_read(&open_event.addr, sizeof(open_event.addr), &(args->addr));

    bpf_printk("Submitting the open event to the userspace");
    bpf_perf_event_output(ctx, &socket_open_events, BPF_F_CURRENT_CPU, &open_event, sizeof(struct socket_open_event_t));
}

static inline __attribute__((__always_inline__)) void process_syscall_close(struct pt_regs *ctx, u64 id, const struct close_args_t *close_args)
{
    s32 ret_val = PT_REGS_RC(ctx);
    if (ret_val < 0)
    {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, close_args->fd);
    struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);

    if (conn_info == NULL)
    {
        // The FD being closed does not represent an IPv4 socket FD.
        bpf_printk("No connection info for fd:%lu", close_args->fd);
        return;
    }

    // Send to the user mode an event indicating the connection was closed.
    struct socket_close_event_t close_event = {};
    close_event.timestamp_ns = bpf_ktime_get_ns();
    close_event.conn_id = conn_info->conn_id;
    close_event.rd_bytes = conn_info->rd_bytes;
    close_event.wr_bytes = conn_info->wr_bytes;

    bpf_printk("Connection closed on [fd:%lu]", close_args->fd);
    bpf_printk("Submitting the close event to the userspace with rd_bytes[%llu] || wr_bytes[%llu]", close_event.rd_bytes, close_event.wr_bytes);
    bpf_perf_event_output(ctx, &socket_close_events, BPF_F_CURRENT_CPU, &close_event, sizeof(struct socket_close_event_t));

    // Remove the connection from the mapping.
    int del = bpf_map_delete_elem(&conn_info_map, &tgid_fd);
    if (del)
    {
        bpf_printk("[process_syscall_close]:error deleting the entry from the conn_info_map:%d\n", del);
    }
}

static inline __attribute__((__always_inline__)) bool is_http_connection(struct conn_info_t *conn_info, const char *buf, size_t count)
{
    // If the connection was already identified as HTTP connection, no need to re-check it.
    if (conn_info->is_http)
    {
        return true;
    }

    // The minimum length of http request or response.
    if (count < 16)
    {
        return false;
    }

    // Reading buffer because directly accessing buffer indices gives permission denied error.
    char check[12];
    bpf_probe_read(&check, sizeof(check), buf);
    bool res = false;
    if (check[0] == 'H' && check[1] == 'T' && check[2] == 'T' && check[3] == 'P')
    {
        res = true;
    }
    if (check[0] == 'G' && check[1] == 'E' && check[2] == 'T')
    {
        res = true;
    }
    if (check[0] == 'P' && check[1] == 'O' && check[2] == 'S' && check[3] == 'T')
    {
        res = true;
    }
    if (check[0] == 'P' && check[1] == 'U' && check[2] == 'T')
    {
        res = true;
    }
    if (check[0] == 'D' && check[1] == 'E' && check[2] == 'L' && check[3] == 'E' && check[4] == 'T' && check[5] == 'E')
    {
        res = true;
    }
    if (check[0] == 'H' && check[1] == 'E' && check[2] == 'A' && check[3] == 'D')
    {
        res = true;
    }
    if (check[0] == 'P' && check[1] == 'A' && check[2] == 'T' && check[3] == 'C' && check[4] == 'H')
    {
        res = true;
    }

    // Add other HTTP request methods here if needed.

    if (res)
    {
        conn_info->is_http = true;
    }

    return res;
}

static __inline void perf_submit_buf(struct pt_regs *ctx, const enum traffic_direction_t direction, char *buf, int buf_size, int offset, struct conn_info_t *conn_info, struct socket_data_event_t *event)

{

    bpf_printk("Direction of traffic of connection:%d is:%d", conn_info->conn_id.fd, direction);

    switch (direction)
    {
    case kEgress:
        event->pos = conn_info->wr_bytes + offset;
        // to validate request data when response comes.
        bpf_printk("Read Bytes:%d (current request)on connection:%d", conn_info->rd_bytes, conn_info->conn_id.fd);
        bpf_probe_read(&event->validate_rd_bytes, sizeof(event->validate_rd_bytes), &conn_info->rd_bytes);
        conn_info->rd_bytes = 0;
        break;
    case kIngress:
        event->pos = conn_info->rd_bytes + offset;
        // wr_bytes = 0, for the first request, but non-zero for the previous response.
        bpf_printk("Written Bytes:%d (previous response)on connection:%d", conn_info->wr_bytes, conn_info->conn_id.fd);
        bpf_probe_read(&event->validate_wr_bytes, sizeof(event->validate_wr_bytes), &conn_info->wr_bytes);
        conn_info->wr_bytes = 0;
        break;
    }

    // 16384 bytes
    // 0x3fff is hexadecimal number of 16383 (all ones in binary)
    // Took 16383 ~ 16KiB, because doing bitwise AND with this number will give the same number hence no chance of decrement in the buf_size.
    asm volatile("%[buf_size] &= 0x3fff;\n" ::[buf_size] "+r"(buf_size)
                 :);
    bpf_probe_read(&event->msg, buf_size & 0x3fff, buf);

    if (buf_size > 0)
    {
        bpf_probe_read(&event->msg_size, sizeof(event->msg_size), &buf_size);
        bpf_printk("Submitting the data event with buffer size:%lu to the userspace", event->msg_size);
        bpf_ringbuf_output(&socket_data_events, event, sizeof(*event), 0);
    }
}

// This function helps to chunk out the buffer data if it is more than the maximum size.
static __inline void perf_submit_wrapper(struct pt_regs *ctx, const enum traffic_direction_t direction, char *buf, int buf_size, struct conn_info_t *conn_info, struct socket_data_event_t *event)
{
    int bytes_sent = 0;
    unsigned int i;
// #pragma clang loop unroll(full)
#pragma unroll
    for (i = 0; i < CHUNK_LIMIT; ++i)
    {
        int bytes_remaining = buf_size - bytes_sent;
        u16 current_size = (bytes_remaining > MAX_MSG_SIZE && (i != CHUNK_LIMIT - 1)) ? MAX_MSG_SIZE : bytes_remaining;
        if (current_size <= 0)
        {
            bpf_printk("Current size is zero or negative, breaking loop.");
            break;
        }
        perf_submit_buf(ctx, direction, buf + bytes_sent, current_size, bytes_sent, conn_info, event);
        bytes_sent += current_size;
        if (buf_size == bytes_sent)
        {
            return;
        }
    }
}

static inline __attribute__((__always_inline__)) void process_data(struct pt_regs *ctx, u64 id, enum traffic_direction_t direction, const struct data_args_t *args, int bytes_count)
{
    // Always check access to pointer before accessing them.
    if (args->buf == NULL)
    {
        return;
    }

    // For read and write syscall, the return code is the number of bytes written or read, so zero means nothing
    // was written or read, and negative means that the syscall failed. Anyhow, we have nothing to do with that syscall.

    if (bytes_count <= 0)
    {
        return;
    }

    u32 pid = id >> 32;
    u64 pid_fd = ((u64)pid << 32) | (u32)args->fd;

    struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &pid_fd);
    if (conn_info == NULL)
    {
        // The FD being read/written does not represent an IPv4 socket FD.
        return;
    }

    // Check if the connection is already HTTP, or check if that's a new connection, check protocol and return true if that's HTTP.
    if (is_http_connection(conn_info, args->buf, bytes_count))
    {

        // Allocate new event.
        u32 kZero = 0;
        // Only lookup no update because each entry of the map is pre-allocated in the socket_data_event_buffer_heap.
        struct socket_data_event_t *event = bpf_map_lookup_elem(&socket_data_event_buffer_heap, &kZero);
        if (!event)
        {
            bpf_printk("[%llu]: unable to allocate memory for data event...", bpf_ktime_get_ns());
            return;
        }

        // Fill the metadata of the data event.
        event->timestamp_ns = bpf_ktime_get_ns();
        event->direction = direction;
        event->conn_id = conn_info->conn_id;

        perf_submit_wrapper(ctx, direction, args->buf, bytes_count, conn_info, event);
    }

    // Update the conn_info total written/read bytes.
    switch (direction)
    {
    case kEgress:
        conn_info->wr_bytes += bytes_count;
        break;
    case kIngress:
        conn_info->rd_bytes += bytes_count;
        break;
    }
}

static inline __attribute__((__always_inline__)) void process_data_chunk(struct pt_regs *ctx, u64 id, enum traffic_direction_t direction, const struct data_args_t *args, int bytes_count)
{
    // check access to pointer before accessing them.
    if (args->iovec == NULL)
    {
        return;
    }

    if (bytes_count <= 0)
    {
        return;
    }

    u32 pid = id >> 32;
    u64 pid_fd = ((u64)pid << 32) | (u32)args->fd;

    struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &pid_fd);
    if (conn_info == NULL)
    {
        // The FD being read/written does not represent an IPv4 socket FD.
        return;
    }
    u32 kZero = 0;

    struct socket_data_event_t *event = bpf_map_lookup_elem(&socket_data_event_buffer_heap, &kZero);
    if (!event)
    {
        bpf_printk("[%llu]: process_data_chunk unable to allocate memory for data event...", bpf_ktime_get_ns());
        return;
    }

    struct iovec iovecStructure, tempIovec;
    if (bpf_probe_read_user(&tempIovec, sizeof(tempIovec), args->iovec))
    {
        bpf_printk("[sys_writev_exit]: Failed to read iovec at %p\n", args->iovec);
        return;
    }
    else if (!is_http_connection(conn_info, tempIovec.iov_base, tempIovec.iov_len))
    {
        bpf_printk("[sys_writev_exit]: Not an http call %p\n", args->iovec);
        return;
    }
    u32 totalBytes = 0;
    for (int index = 0; totalBytes < bytes_count && index < 10; index++)
    {
        if (bpf_probe_read_user(&iovecStructure, sizeof(iovecStructure), args->iovec + index))
        {
            bpf_printk("[sys_writev_exit]: Failed to read iovec at %p\n", args->iovec + index);
            break;
        }
        totalBytes += iovecStructure.iov_len;
        event->timestamp_ns = bpf_ktime_get_ns();
        event->direction = direction;
        event->conn_id = conn_info->conn_id;
        perf_submit_wrapper(ctx, direction, iovecStructure.iov_base, iovecStructure.iov_len, conn_info, event);
    }
    // Update the conn_info total written/read bytes.
    switch (direction)
    {
    case kEgress:
        conn_info->wr_bytes += bytes_count;
        break;
    case kIngress:
        conn_info->rd_bytes += bytes_count;
        break;
    }
}