// SPDX-License-Identifier: GPL-3.0-or-later
//
// eBPF part of wachposten-daemon, loaded by aya.
//
// Only syscall tracepoints are used. Their argument layout is fixed, so no kernel structures
// are read and the object runs on any kernel with BPF ring buffers (5.8+) without CO-RE.
//
//  - Program starts: execve/execveat record the file name and the first arguments on entry and
//    report them on a successful return. This sees scripts run through an interpreter and
//    programs started from memory (memfd), which fanotify does not.
//  - Writes: openat/open with write intent, rename, symlink, link and unlink report the target
//    path and the process, so the daemon can say which program changed a persistence entry and
//    notice a process that encrypts many files. Renames also carry the old name.
//
// Filtering by path happens in user space.

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *src) =
    (void *)BPF_FUNC_probe_read_user;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *src) =
    (void *)BPF_FUNC_probe_read_user_str;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) =
    (void *)BPF_FUNC_probe_read_kernel;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
    (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;

#define PATH_LEN 256
#define ARG_LEN 128
#define MAX_ARGS 4

#define KIND_EXEC 1
#define KIND_WRITE 2

#define OP_OPEN 0
#define OP_RENAME 1
#define OP_SYMLINK 2
#define OP_LINK 3
#define OP_UNLINK 4

#define AT_REMOVEDIR 0x200

// Must match `RawEvent` in src/ebpf.rs.
struct event {
    __u32 kind;
    __u32 pid;  // thread group id (the process id)
    __u32 uid;
    __s32 dirfd;
    __u32 flags; // open flags, execveat flags
    __u32 op;
    char comm[16];
    char path[PATH_LEN];
    char args[MAX_ARGS][ARG_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 << 20);
} EVENTS SEC(".maps");

// Program starts between syscall entry and return, by thread.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct event);
} PENDING SEC(".maps");

// Room to build an event; it is too large for the BPF stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} SCRATCH SEC(".maps");

// Layout of syscall tracepoints: 8 bytes of common fields, the syscall number, then one
// 8-byte slot per argument starting at offset 16.
struct sys_enter {
    __u64 common;
    __s64 nr;
    __u64 args[6];
};

struct sys_exit {
    __u64 common;
    __s64 nr;
    __s64 ret;
};

static __always_inline struct event *scratch(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&SCRATCH, &zero);
}

static __always_inline int exec_enter(const char *filename, const char *const *argv, __s32 dirfd,
                                      __u32 flags) {
    struct event *e = scratch();
    if (!e)
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    e->kind = KIND_EXEC;
    e->pid = id >> 32;
    e->dirfd = dirfd;
    e->flags = flags;
    e->op = 0;
    bpf_probe_read_user_str(e->path, PATH_LEN, filename);
#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg = 0;
        e->args[i][0] = 0;
        if (argv && bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) == 0 && arg)
            bpf_probe_read_user_str(e->args[i], ARG_LEN, arg);
    }
    bpf_map_update_elem(&PENDING, &id, e, BPF_ANY);
    return 0;
}

static __always_inline int exec_exit(const struct sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct event *pending = bpf_map_lookup_elem(&PENDING, &id);
    if (!pending)
        return 0;
    if (ctx->ret == 0) {
        struct event *e = bpf_ringbuf_reserve(&EVENTS, sizeof(struct event), 0);
        if (e) {
            bpf_probe_read_kernel(e, sizeof(struct event), pending);
            // After the exec: the new program's name and the (possibly changed) user.
            bpf_get_current_comm(e->comm, sizeof(e->comm));
            e->uid = (__u32)bpf_get_current_uid_gid();
            bpf_ringbuf_submit(e, 0);
        }
    }
    bpf_map_delete_elem(&PENDING, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_enter(struct sys_enter *ctx) {
    return exec_enter((const char *)ctx->args[0], (const char *const *)ctx->args[1], -100, 0);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int execveat_enter(struct sys_enter *ctx) {
    return exec_enter((const char *)ctx->args[1], (const char *const *)ctx->args[2],
                      (__s32)ctx->args[0], (__u32)ctx->args[4]);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int execve_exit(struct sys_exit *ctx) {
    return exec_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int execveat_exit(struct sys_exit *ctx) {
    return exec_exit(ctx);
}

#define O_WRONLY 01
#define O_RDWR 02
#define O_CREAT 0100
#define O_TRUNC 01000

// Package managers running as root write thousands of files that are checked by package
// verification anyway; their events are not sent at all.
static __always_inline int is_package_manager(const char *comm) {
    if (comm[0] == 'r' && comm[1] == 'p' && comm[2] == 'm')
        return 1; // rpm, rpmkeys, rpm-ostree
    if (comm[0] == 'd' && comm[1] == 'n' && comm[2] == 'f' && (comm[3] == 0 || comm[3] == '5'))
        return 1;
    if (comm[0] == 'd' && comm[1] == 'p' && comm[2] == 'k' && comm[3] == 'g')
        return 1;
    if (comm[0] == 'p' && comm[1] == 'a' && comm[2] == 'c' && comm[3] == 'k' && comm[4] == 'a' &&
        comm[5] == 'g' && comm[6] == 'e' && comm[7] == 'k')
        return 1; // packagekitd
    return 0;
}

// `old` (may be null) is the old name of a rename, relative to `olddirfd`, which goes into
// `flags`.
static __always_inline int write_event2(const char *path, __s32 dirfd, __u32 flags, __u32 op,
                                        const char *old) {
    __u64 uidgid = bpf_get_current_uid_gid();
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if ((__u32)uidgid == 0 && is_package_manager(comm))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&EVENTS, sizeof(struct event), 0);
    if (!e)
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    e->kind = KIND_WRITE;
    e->pid = id >> 32;
    e->uid = (__u32)uidgid;
    e->dirfd = dirfd;
    e->flags = flags;
    e->op = op;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    if (bpf_probe_read_user_str(e->path, PATH_LEN, path) < 0)
        e->path[0] = 0;
    e->args[0][0] = 0;
    if (old && bpf_probe_read_user_str(e->args[0], ARG_LEN, old) < 0)
        e->args[0][0] = 0;
    e->args[1][0] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int write_event(const char *path, __s32 dirfd, __u32 flags, __u32 op) {
    return write_event2(path, dirfd, flags, op, 0);
}

static __always_inline int writes(__u32 flags) {
    return flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_enter(struct sys_enter *ctx) {
    __u32 flags = (__u32)ctx->args[2];
    if (!writes(flags))
        return 0;
    return write_event((const char *)ctx->args[1], (__s32)ctx->args[0], flags, OP_OPEN);
}

SEC("tracepoint/syscalls/sys_enter_open")
int open_enter(struct sys_enter *ctx) {
    __u32 flags = (__u32)ctx->args[1];
    if (!writes(flags))
        return 0;
    return write_event((const char *)ctx->args[0], -100, flags, OP_OPEN);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int renameat2_enter(struct sys_enter *ctx) {
    return write_event2((const char *)ctx->args[3], (__s32)ctx->args[2], (__u32)ctx->args[0],
                        OP_RENAME, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int renameat_enter(struct sys_enter *ctx) {
    return write_event2((const char *)ctx->args[3], (__s32)ctx->args[2], (__u32)ctx->args[0],
                        OP_RENAME, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int rename_enter(struct sys_enter *ctx) {
    return write_event2((const char *)ctx->args[1], -100, (__u32)-100, OP_RENAME,
                        (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int symlinkat_enter(struct sys_enter *ctx) {
    return write_event((const char *)ctx->args[2], (__s32)ctx->args[1], 0, OP_SYMLINK);
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int symlink_enter(struct sys_enter *ctx) {
    return write_event((const char *)ctx->args[1], -100, 0, OP_SYMLINK);
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int linkat_enter(struct sys_enter *ctx) {
    return write_event((const char *)ctx->args[3], (__s32)ctx->args[2], 0, OP_LINK);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int unlinkat_enter(struct sys_enter *ctx) {
    if ((__u32)ctx->args[2] & AT_REMOVEDIR)
        return 0;
    return write_event((const char *)ctx->args[1], (__s32)ctx->args[0], 0, OP_UNLINK);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int unlink_enter(struct sys_enter *ctx) {
    return write_event((const char *)ctx->args[0], -100, 0, OP_UNLINK);
}

char LICENSE[] SEC("license") = "GPL";
