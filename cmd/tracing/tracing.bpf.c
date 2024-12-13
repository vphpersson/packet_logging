//go:build ignore

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

// execve tracing

#define ARGLEN 32
#define ARGSIZE 1024

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} execve_events SEC(".maps");

struct execve_event {
	u8  filename[ARGSIZE];
	u8  argv[ARGLEN][ARGSIZE];
	u32 argc; // set to ARGLEN + 1 if there were more than ARGLEN arguments
	u32 uid;
	u32 gid;
	u32 pid;
	u32 ppid;
    u8 interactive;

	u8  comm[ARGSIZE];
};
struct execve_event *unused2 __attribute__((unused));

struct exec_info {
	u16 common_type;            // offset=0,  size=2
	u8  common_flags;           // offset=2,  size=1
	u8  common_preempt_count;   // offset=3,  size=1
	s32 common_pid;             // offset=4,  size=4

	s32             syscall_nr; // offset=8,  size=4
	u32             pad;        // offset=12, size=4 (pad)
	const u8        *filename;  // offset=16, size=8 (ptr)
	const u8 *const *argv;      // offset=24, size=8 (ptr)
	const u8 *const *envp;      // offset=32, size=8 (ptr)
};

static struct execve_event zero_execve_event SEC(".rodata") = {
	.filename = {0},
	.argv = {},
	.argc = 0,
	.uid = 0,
	.gid = 0,
	.pid = 0,
	.ppid = 0,
    .interactive = 0,
	.comm = {0},
};

SEC("tracepoint/syscalls/sys_enter_execve")
s32 enter_execve(struct exec_info *execve_ctx) {

	struct execve_event *event;
	event = bpf_ringbuf_reserve(&execve_events, sizeof(struct execve_event), 0);
	if (!event) {
//		LOG0("could not reserve events ringbuf memory");
		return 1;
	}

    // Zero out the event for safety. If we don't do this, we risk sending random kernel memory back to userspace.
    s32 ret = bpf_probe_read_kernel(event, sizeof(event), &zero_execve_event);
    if (ret) {
//        LOG1("zero out event: %d", ret);
        bpf_ringbuf_discard(event, 0);
        return 1;
    }

    u64 uid_gid = bpf_get_current_uid_gid();
	event->uid = bpf_htonl((u32) uid_gid);
    event->gid = bpf_htonl(uid_gid >> 32);

    event->pid = bpf_htonl(bpf_get_current_pid_tgid() >> 32);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = bpf_htonl(BPF_CORE_READ(task, real_parent, pid));


//   struct files_struct *files = task->files;
//   struct fdtable *fdt = files->fdt;

//    if (fdt) {
//        struct file *file_stdin = fdt->fd[0];
//        struct file *file_stderr = fdt->fd[2];

//        if (!(!file_stdin || !file_stderr)) {
//            dev_t stdin_dev = file_stdin->f_inode->i_rdev;
//            dev_t stderr_dev = file_stderr->f_inode->i_rdev;
//
//            struct tty_struct *tty = task->signal->tty;
//            if (tty) {
//                if (stdin_dev == tty->dev->id && stderr_dev == tty->dev->id) {
//                    event->interactive = 1;
//                }
//            }
//        }
//    }

    ret = bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (ret) {
//    	LOG1("could not get current comm: %d", ret);
    	bpf_ringbuf_discard(event, 0);
    	return 1;
    }

    // Write the filename in addition to argv[0] because the filename contains
    // the full path to the file which could be more useful in some situations.
    ret = bpf_probe_read_user_str(&event->filename, sizeof(event->filename), execve_ctx->filename);
    if (ret < 0) {
//        LOG1("could not read filename into event struct: %d", ret);
        bpf_ringbuf_discard(event, 0);
        return 1;
    }

    for (u32 i = 0; i < ARGLEN; i++) {
        if (!(&execve_ctx->argv[i])) {
            goto out;
        }

        const u8 *argp = NULL;
        ret = bpf_probe_read_user(&argp, sizeof(argp), &execve_ctx->argv[i]);
        if (ret || !argp) {
            goto out;
        }

        ret = bpf_probe_read_user_str(event->argv[i], sizeof(event->argv[i]), argp);
        if (ret < 0) {
//            LOG2("read argv %u: %d", i, ret);
            goto out;
        }

        event->argc++;
    }

    // This won't get hit if we `goto out` in the loop above. This is to signify
    // to userspace that we couldn't copy all of the arguments because it
    // exceeded ARGLEN.
    event->argc++;

out:
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// connect tracing

#define AF_INET 2

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} connect_events SEC(".maps");

struct connect_event {
    __u32 saddr_v4;
    __u8 saddr_v6[16];
    __u32 daddr_v4;
    __u8 daddr_v6[16];
    __u16 sport;
    __u16 dport;

    __u16 af;

    u64 ts_ns;
    u32 pid;
    u32 ppid;

    u32 uid;
    u32 gid;

    u8 comm[TASK_COMM_LEN];
};
struct connect_event *unused __attribute__((unused));

static int trace_connect(struct sock *sk) {
    u64 timestamp = bpf_ktime_get_ns();

    struct connect_event *event;
    event = bpf_ringbuf_reserve(&connect_events, sizeof(struct connect_event), 0);
    if (!event) {
        return 0;
    }

    event->ts_ns = timestamp;

    u64 uid_gid = bpf_get_current_uid_gid();
	event->uid = bpf_htonl((u32) uid_gid);
    event->gid = bpf_htonl(uid_gid >> 32);

    event->pid = bpf_htonl(bpf_get_current_pid_tgid() >> 32);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = bpf_htonl(BPF_CORE_READ(task, real_parent, pid));

	event->dport = sk->__sk_common.skc_dport;
	event->sport = bpf_htons(sk->__sk_common.skc_num);
    event->af = bpf_htons(sk->__sk_common.skc_family);

    if (sk->__sk_common.skc_family == AF_INET) {
        event->saddr_v4 = sk->__sk_common.skc_rcv_saddr;
        event->daddr_v4 = sk->__sk_common.skc_daddr;
    } else {
    	BPF_CORE_READ_INTO(event->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    	BPF_CORE_READ_INTO(event->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

	bpf_get_current_comm(&event->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
    return trace_connect(sk);
}
