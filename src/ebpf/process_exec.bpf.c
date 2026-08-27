// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "process_exec.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ---------------------------------------------------------- */
/* Constants                                                   */
/* ---------------------------------------------------------- */

#define AF_INET_VALUE 2

#define O_WRONLY_VALUE 1
#define O_RDWR_VALUE   2
#define O_CREAT_VALUE  64
#define O_TRUNC_VALUE  512
#define O_APPEND_VALUE 1024

/* ---------------------------------------------------------- */
/* Maps                                                        */
/* ---------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

/* ---------------------------------------------------------- */
/* Helpers                                                      */
/* ---------------------------------------------------------- */

static __always_inline void init_event(struct ks_event *e)
{
    /*
     * The expanded ks_event contains fields which are not used
     * by every event type.
     *
     * Zero the complete structure so userspace never receives
     * stale/uninitialized telemetry.
     */
    __builtin_memset(e, 0, sizeof(*e));
}

/* ---------------------------------------------------------- */
/* EXEC                                                         */
/* ---------------------------------------------------------- */

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    struct ks_event *e;

    u64 ts;
    u64 id;
    u64 uid_gid;

    pid_t pid;
    unsigned fname_off;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    if (min_duration_ns)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

    if (!e)
        return 0;

    init_event(e);

    task = (struct task_struct *)bpf_get_current_task();

    uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = ts;
    e->duration_ns = 0;

    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->exit_code = 0;

    e->type = KS_EVENT_EXEC;
    e->exit_event = false;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    fname_off = ctx->__data_loc_filename & 0xFFFF;

    bpf_probe_read_str(
        e->filename,
        sizeof(e->filename),
        (void *)ctx + fname_off
    );

    bpf_ringbuf_submit(e, 0);

    return 0;
}

/* ---------------------------------------------------------- */
/* NETWORK CONNECT                                              */
/* ---------------------------------------------------------- */

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr;
    struct ks_event *e;

    u64 id;
    u64 uid_gid;

    pid_t pid;

    const struct sockaddr *user_addr;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    user_addr = (const struct sockaddr *)ctx->args[1];

    if (!user_addr)
        return 0;

    if (bpf_probe_read_user(
            &addr,
            sizeof(addr),
            user_addr) != 0)
        return 0;

    if (addr.sin_family != AF_INET_VALUE)
        return 0;

    if (addr.sin_port == 0)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

    if (!e)
        return 0;

    init_event(e);

    uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->duration_ns = 0;

    e->pid = pid;

    {
        struct task_struct *task;

        task = (struct task_struct *)bpf_get_current_task();

        e->ppid = BPF_CORE_READ(
            task,
            real_parent,
            tgid
        );
    }

    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->exit_code = 0;

    e->type = KS_EVENT_NETWORK;
    e->exit_event = false;

    bpf_get_current_comm(
        e->comm,
        sizeof(e->comm)
    );

    e->dst_ipv4 = addr.sin_addr.s_addr;
    e->dst_port = addr.sin_port;

    e->address_family = AF_INET_VALUE;

    /*
     * We are tracing connect().
     *
     * Protocol is not reliably available from sockaddr_in
     * alone, so leave it as zero rather than guessing.
     */
    e->protocol = 0;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

/* ---------------------------------------------------------- */
/* FILE OPEN / CREATE                                           */
/* ---------------------------------------------------------- */

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct ks_event *e;
    struct task_struct *task;

    u64 id;
    u64 uid_gid;

    pid_t pid;

    const char *filename;
    long flags;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    /*
     * openat arguments:
     *
     * args[0] = dirfd
     * args[1] = filename
     * args[2] = flags
     * args[3] = mode
     */
    filename =
        (const char *)ctx->args[1];

    flags = ctx->args[2];

    if (!filename)
        return 0;

    /*
     * Ignore extremely noisy kernel/system read activity.
     * These paths generate huge amounts of benign telemetry
     * from systemd, udev, oomd, desktop services, etc.
     */
    char path_probe[KS_MAX_PATH_LEN];

    if (bpf_probe_read_user_str(
            path_probe,
            sizeof(path_probe),
            filename) <= 0)
        return 0;

    if ((path_probe[0] == '/' &&
         path_probe[1] == 'p' &&
         path_probe[2] == 'r' &&
         path_probe[3] == 'o' &&
         path_probe[4] == 'c' &&
         path_probe[5] == '/') ||
        (path_probe[0] == '/' &&
         path_probe[1] == 's' &&
         path_probe[2] == 'y' &&
         path_probe[3] == 's' &&
         path_probe[4] == '/') ||
        (path_probe[0] == '/' &&
         path_probe[1] == 'r' &&
         path_probe[2] == 'u' &&
         path_probe[3] == 'n' &&
         path_probe[4] == '/' &&
         path_probe[5] == 'u' &&
         path_probe[6] == 'd' &&
         path_probe[7] == 'e' &&
         path_probe[8] == 'v' &&
         path_probe[9] == '/')) {

        /*
         * Keep writes/creates even under noisy system paths.
         * Ignore ordinary read-only opens.
         */
        if (!(flags & O_WRONLY_VALUE) &&
            !(flags & O_RDWR_VALUE) &&
            !(flags & O_CREAT_VALUE) &&
            !(flags & O_TRUNC_VALUE) &&
            !(flags & O_APPEND_VALUE))
            return 0;
    }

    e = bpf_ringbuf_reserve(
        &rb,
        sizeof(*e),
        0
    );

    if (!e)
        return 0;

    init_event(e);

    uid_gid = bpf_get_current_uid_gid();

    task =
        (struct task_struct *)bpf_get_current_task();

    e->timestamp_ns =
        bpf_ktime_get_ns();

    e->duration_ns = 0;

    e->pid = pid;

    e->ppid =
        BPF_CORE_READ(
            task,
            real_parent,
            tgid
        );

    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->type = KS_EVENT_FILE;

    e->exit_event = false;

    bpf_get_current_comm(
        e->comm,
        sizeof(e->comm)
    );

    /*
     * Determine the operation based on open flags.
     */
    if (flags & O_CREAT_VALUE) {
        e->file_operation = KS_FILE_CREATE;
    }
    else if (flags & O_TRUNC_VALUE) {
        e->file_operation = KS_FILE_WRITE;
    }
    else if ((flags & O_WRONLY_VALUE) ||
             (flags & O_RDWR_VALUE) ||
             (flags & O_APPEND_VALUE)) {
        e->file_operation = KS_FILE_WRITE;
    }
    else {
        e->file_operation = KS_FILE_OPEN;
    }

    /*
     * Capture userspace filename.
     */
    bpf_probe_read_user_str(
        e->file_path,
        sizeof(e->file_path),
        filename
    );

    /*
     * Keep filename empty for FILE events.
     * file_path contains the actual path.
     */
    e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    return 0;
}


/* ---------------------------------------------------------- */
/* PRIVILEGE EXECUTION                                         */
/* ---------------------------------------------------------- */

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct ks_event *e;
    struct task_struct *task;
    u64 id, uid_gid;
    pid_t pid;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    init_event(e);

    task = (struct task_struct *)bpf_get_current_task();
    uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->type = KS_EVENT_PRIVILEGE;
    e->privilege_operation = KS_PRIV_UID_CHANGE;
    e->old_uid = (u32)uid_gid;
    e->new_uid = (u32)ctx->args[0];

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx)
{
    struct ks_event *e;
    struct task_struct *task;
    u64 id, uid_gid;
    pid_t pid;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    init_event(e);

    task = (struct task_struct *)bpf_get_current_task();
    uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->type = KS_EVENT_PRIVILEGE;
    e->privilege_operation = KS_PRIV_GID_CHANGE;
    e->old_gid = (u32)(uid_gid >> 32);
    e->new_gid = (u32)ctx->args[0];

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}



/* ---------------------------------------------------------- */
/* PRIVILEGE EXECUTION                                         */
/* ---------------------------------------------------------- */

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_privileged_exec(struct trace_event_raw_sys_enter *ctx)
{
    struct ks_event *e;
    struct task_struct *task;
    u64 id;
    u64 uid_gid;
    pid_t pid;

    uid_gid = bpf_get_current_uid_gid();

    /* Only generate a privilege event when running as root. */
    if ((u32)uid_gid != 0)
        return 0;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    init_event(e);

    task = (struct task_struct *)bpf_get_current_task();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->type = KS_EVENT_PRIVILEGE;
    e->privilege_operation = KS_PRIV_EXEC_PRIVILEGED;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    return 0;
}


/* ---------------------------------------------------------- */
/* EXIT                                                         */
/* ---------------------------------------------------------- */

SEC("tp/sched/sched_process_exit")
int handle_exit(
    struct trace_event_raw_sched_process_template *ctx)
{
    struct task_struct *task;
    struct ks_event *e;

    u64 id;
    u64 ts;
    u64 uid_gid;

    u64 *start_ts;
    u64 duration_ns = 0;

    pid_t pid;
    pid_t tid;

    id = bpf_get_current_pid_tgid();

    pid = id >> 32;
    tid = (u32)id;

    /*
     * Only report thread-group leaders.
     */
    if (pid != tid)
        return 0;

    start_ts =
        bpf_map_lookup_elem(
            &exec_start,
            &pid
        );

    if (start_ts)
        duration_ns =
            bpf_ktime_get_ns() - *start_ts;
    else if (min_duration_ns)
        return 0;

    bpf_map_delete_elem(
        &exec_start,
        &pid
    );

    if (min_duration_ns &&
        duration_ns < min_duration_ns)
        return 0;

    e =
        bpf_ringbuf_reserve(
            &rb,
            sizeof(*e),
            0
        );

    if (!e)
        return 0;

    init_event(e);

    task =
        (struct task_struct *)bpf_get_current_task();

    uid_gid =
        bpf_get_current_uid_gid();

    ts =
        bpf_ktime_get_ns();

    e->timestamp_ns = ts;
    e->duration_ns = duration_ns;

    e->pid = pid;

    e->ppid =
        BPF_CORE_READ(
            task,
            real_parent,
            tgid
        );

    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->exit_code =
        (BPF_CORE_READ(
            task,
            exit_code
        ) >> 8) & 0xff;

    e->type = KS_EVENT_EXIT;
    e->exit_event = true;

    bpf_get_current_comm(
        e->comm,
        sizeof(e->comm)
    );

    e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    return 0;
}
