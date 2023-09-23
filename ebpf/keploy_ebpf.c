// +build ignore

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "k_structs.h"
#include "k_maps.h"
#include "k_helpers.h"

// #) Hooks for Ingress
// KProbing in order to capture the incoming requests and responses.

// accept sys call
SEC("kprobe/sys_accept")
int syscall__probe_entry_accept(struct pt_regs *ctx)
{

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    if (!__ctx)
    {
        bpf_printk("[sys_accept_entry]:failed to load original ctx");
        return 0;
    }

    bpf_printk("[sys_accept_entry]:called for [PID:%lu]\n", pid);

    // Create a new accept_args_t struct
    struct accept_args_t accept_args = {};

    accept_args.addr = (struct sockaddr_in *)PT_REGS_PARM2_CORE(__ctx);
    bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);

    return 0;
}

SEC("kretprobe/sys_accept")
int syscall__probe_ret_accept(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    bpf_printk("[sys_accept_exit]:called for [PID:%lu]\n", pid);

    // // Pulling the addr from the map.
    const struct accept_args_t *accept_args = bpf_map_lookup_elem(&active_accept_args_map, &id);
    if (accept_args)
    {
        process_syscall_accept(ctx, id, accept_args);

        int del = bpf_map_delete_elem(&active_accept_args_map, &id);
        if (del)
        {
            bpf_printk("[sys_accept_exit]:error deleting the entry from the active_accept_args_map:%d\n", del);
        }
    }
    return 0;
}

// accept4 sys call
SEC("kprobe/sys_accept4")
int syscall__probe_entry_accept4(struct pt_regs *ctx)
{

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    if (!__ctx)
    {
        bpf_printk("[sys_accept4_entry]:failed to load original ctx");
        return 0;
    }

    bpf_printk("[sys_accept4_entry]:called for [PID:%lu]\n", pid);

    // Create a new accept_args_t struct
    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)PT_REGS_PARM2_CORE(__ctx);
    bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);

    return 0;
}

SEC("kretprobe/sys_accept4")
int syscall__probe_ret_accept4(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    bpf_printk("[sys_accept4_exit]:called for [PID:%lu]\n", pid);

    // // Pulling the addr from the map.
    const struct accept_args_t *accept_args = bpf_map_lookup_elem(&active_accept_args_map, &id);
    if (accept_args)
    {
        process_syscall_accept(ctx, id, accept_args);

        int del = bpf_map_delete_elem(&active_accept_args_map, &id);
        if (del)
        {
            bpf_printk("[sys_accept4_exit]:error deleting the entry from the active_accept_args_map:%d\n", del);
        }
    }
    return 0;
}

// read sys call
SEC("kprobe/sys_read")
int syscall__probe_entry_read(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    if (!__ctx)
    {
        bpf_printk("[sys_read_entry]:failed to load original ctx");
        return 0;
    }

    bpf_printk("[sys_read_entry]:called for [PID:%lu]\n", pid);

    // Stash arguments
    struct data_args_t read_args = {};

    read_args.fd = (int)PT_REGS_PARM1_CORE(__ctx);
    char *read_buf = (char *)PT_REGS_PARM2_CORE(__ctx);

    if (!read_buf)
    {
        bpf_printk("[sys_read_entry]:read buf is null");
        return 0;
    }

    read_args.buf = read_buf;
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_read")
int syscall__probe_ret_read(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    // The return code the syscall is the number of bytes read as well.
    size_t bytes_count = PT_REGS_RC(ctx); // Also stands for return code.

    if ((int)bytes_count >= 16)
    {
        bpf_printk("[sys_read_exit]: called for pid_tgid:%llu", id);
    }

    bpf_printk("[sys_read_exit]:called for [PID:%lu] having return code:%d", pid, bytes_count);

    struct data_args_t *read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (read_args)
    {
        // // kIngress is an enum value that let's the process_data function
        // // to know whether the input buffer is incoming or outgoing.

        process_data(ctx, id, kIngress, read_args, bytes_count);

        int del = bpf_map_delete_elem(&active_read_args_map, &id);
        if (del)
        {
            bpf_printk("[sys_read_exit]:error deleting the entry from the active_read_args_map:%d\n", del);
        }
    }
    return 0;
}

// write sys call
SEC("kprobe/sys_write")
int syscall__probe_entry_write(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    if (!__ctx)
    {
        bpf_printk("[sys_write_entry]:failed to load original ctx");
        return 0;
    }

    bpf_printk("[sys_write_entry]:called for [PID:%lu]\n", pid);

    // Stash arguments
    struct data_args_t write_args = {};

    write_args.fd = (int)PT_REGS_PARM1_CORE(__ctx);
    char *write_buf = (char *)PT_REGS_PARM2_CORE(__ctx);

    if (!write_buf)
    {
        bpf_printk("[sys_write_entry]:write buf is null");
        return 0;
    }

    write_args.buf = write_buf;
    bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_write")
int syscall__probe_ret_write(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    // The return code the syscall is the number of bytes read as well.
    size_t bytes_count = PT_REGS_RC(ctx); // Also stands for return code.

    if ((int)bytes_count >= 16)
    {
        bpf_printk("[sys_write_exit]: called for pid_tgid:%llu", id);
    }

    bpf_printk("[sys_write_exit]:called for [PID:%lu] having return code:%d", pid, bytes_count);

    struct data_args_t *write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (write_args)
    {
        // // KEgress is an enum value that let's the process_data function
        // // to know whether the output buffer is incoming or outgoing.

        process_data(ctx, id, kEgress, write_args, bytes_count);

        int del = bpf_map_delete_elem(&active_write_args_map, &id);
        if (del)
        {
            bpf_printk("[sys_write_exit]:error deleting the entry from the active_write_args_map:%d\n", del);
        }
    }
    return 0;
}

// writev sys call, used for nodejs http response
SEC("kprobe/sys_writev")
int syscall__probe_entry_writev(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    if (!__ctx)
    {
        bpf_printk("[sys_writev_entry]:failed to load original ctx");
        return 0;
    }

    struct data_args_t write_args = {};

    write_args.fd = (int)PT_REGS_PARM1_CORE(__ctx);
    struct iovec *iovecs = (struct iovec *)PT_REGS_PARM2_CORE(__ctx);

    if (!iovecs)
    {
        bpf_printk("[sys_writev_entry]: iovecs is null\n");
        return 0;
    }
    write_args.iovec = iovecs;
    bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);

    return 0;
}

SEC("kretprobe/sys_writev")
int syscall__probe_ret_writev(struct pt_regs *ctx)
{

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    size_t bytes_count = PT_REGS_RC(ctx);

    struct data_args_t *write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (write_args)
    {
        bpf_printk("[sys_writev_exit]: byteCount: %d\n", bytes_count);
        process_data_chunk(ctx, id, kEgress, write_args, bytes_count);
        int del = bpf_map_delete_elem(&active_write_args_map, &id);
        if (del)
        {
            bpf_printk("[sys_writev_exit]:error deleting the entry from the active_writev_args_map:%d\n", del);
        }
    }
    return 0;
}


// sendto sys call
// This syscall is used to get the response from a python application.
SEC("kprobe/sys_sendto")
int syscall__probe_entry_sendto(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    if (!__ctx)
    {
        bpf_printk("[sys_sendto_entry]:failed to load original ctx");
        return 0;
    }

    struct data_args_t write_args = {};

    write_args.fd = (int)PT_REGS_PARM1_CORE(__ctx);
    char *buffer = (char *)PT_REGS_PARM2_CORE(__ctx);
    if (!buffer)
    {
        bpf_printk("[sys_sendto_entry]: buffer is null\n");
        return 0;
    }
    write_args.buf = buffer;
    bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_sendto")
int syscall__probe_ret_sendto(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    size_t bytes_count = PT_REGS_RC(ctx);

    struct data_args_t *write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (write_args)
    {
        process_data(ctx, id, kEgress, write_args, bytes_count);
        int del = bpf_map_delete_elem(&active_write_args_map, &id);
        if (del)
        {
            bpf_printk("[sys_sendto_exit]:error deleting the entry from the active_writev_args_map:%d\n", del);
        }
    }
    return 0;
}

// recvfrom sys call
// This call is used to get the request that is made to the python application.
SEC("kprobe/sys_recvfrom")
int syscall__probe_entry_recvfrom(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
   
   u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    if (!__ctx)
    {
        bpf_printk("[sys_recvfrom_entry]:failed to load original ctx");
        return 0;
    }

    // Stash arguments
    struct data_args_t read_args = {};

    read_args.fd = (int)PT_REGS_PARM1_CORE(__ctx);
    char *read_buf = (char *)PT_REGS_PARM2_CORE(__ctx);

    if (!read_buf)
    {
        bpf_printk("[sys_recvfrom_entry]:read buf is null");
        return 0;
    }

    read_args.buf = read_buf;
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_recvfrom")
int syscall__probe_ret_recvfrom(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }
    
    size_t bytes_count = PT_REGS_RC(ctx); // Also stands for return code.

    bpf_printk("[sys_recvfrom_exit]:called for [PID:%lu] having return code:%d", pid, bytes_count);

    struct data_args_t *read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (read_args)
    {
        // // kIngress is an enum value that let's the process_data function
        // // to know whether the input buffer is incoming or outgoing.

        process_data(ctx, id, kIngress, read_args, bytes_count);

        int del = bpf_map_delete_elem(&active_read_args_map, &id);
        if (del)
        {
            bpf_printk("[sys_recvfrom_exit]:error deleting the entry from the active_read_args_map:%d\n", del);
        }
    }
    return 0;
}


// close sys call
//  // original signature: int close(int fd)
SEC("kprobe/sys_close")
int syscall__probe_entry_close(struct pt_regs *ctx, int fd)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    if (!__ctx)
    {
        bpf_printk("[sys_close_entry]:failed to load original ctx");
        return 0;
    }

    bpf_printk("[sys_close_entry]:called for [PID:%lu]\n", pid);

    struct close_args_t close_args = {};
    close_args.fd = (PT_REGS_PARM1_CORE(__ctx));

    bpf_map_update_elem(&active_close_args_map, &id, &close_args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_close")
int syscall__probe_ret_close(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 kZero = 0;
    u32 *appPid = bpf_map_lookup_elem(&app_pid_map, &kZero);
    if (appPid)
    {
        if (pid != *appPid)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    bpf_printk("[sys_close_exit]:called for [PID:%lu]\n", pid);

    struct close_args_t *close_args = bpf_map_lookup_elem(&active_close_args_map, &id);
    if (close_args)
    {
        process_syscall_close(ctx, id, close_args);
        int del = bpf_map_delete_elem(&active_close_args_map, &id);
        if (del)
        {
            bpf_printk("[sys_close_exit]:error deleting the entry from the active_close_args_map:%d\n", del);
        }
    }
    return 0;
}

// This is important license, DO NOT REMOVE THIS
char _license[] SEC("license") = "GPL";
