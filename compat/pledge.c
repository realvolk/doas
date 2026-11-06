/*
 * Copyright (c) 2026 realvolk <https://github.com/realvolk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Seccomp-based approximation of OpenBSD's pledge(2). Syscall
 * tables are maintained locally and are not 1:1 with OpenBSD's
 * curated promises.
 */

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include "pledge.h"

static const int common_syscalls[] = {
	__NR_exit, __NR_exit_group, __NR_rt_sigreturn,
	__NR_brk, __NR_mmap, __NR_munmap, __NR_mprotect, __NR_madvise,
	__NR_getpid, __NR_gettid, __NR_getppid,
	__NR_clock_gettime, __NR_gettimeofday, __NR_nanosleep,
	__NR_clock_nanosleep, __NR_clock_getres,
	__NR_futex, __NR_set_tid_address, __NR_set_robust_list,
	__NR_arch_prctl, __NR_rt_sigaction, __NR_rt_sigprocmask,
	__NR_sigaltstack,
	__NR_prctl, __NR_seccomp, __NR_getrandom, __NR_rseq,
	__NR_landlock_restrict_self,
	__NR_prlimit64, __NR_uname, __NR_sysinfo,
	__NR_membarrier, __NR_sched_getaffinity, __NR_sched_setaffinity,
	__NR_getrlimit, __NR_setrlimit, __NR_getrusage,
	__NR_getitimer, __NR_setitimer, __NR_sched_yield,
	__NR_umask,
	__NR_landlock_create_ruleset, __NR_landlock_add_rule,
	-1
};

static const int stdio_syscalls[] = {
	__NR_read, __NR_write, __NR_readv, __NR_writev,
	__NR_close, __NR_fstat, __NR_lseek, __NR_fcntl,
	__NR_dup, __NR_dup2, __NR_dup3,
	__NR_fsync, __NR_fdatasync,
	__NR_poll, __NR_ppoll, __NR_select, __NR_pselect6,
	__NR_pipe, __NR_pipe2,
	__NR_socket, __NR_connect, __NR_sendto, __NR_recvfrom,
	__NR_sendmsg, __NR_recvmsg, __NR_shutdown,
	__NR_getuid, __NR_geteuid, __NR_getgid, __NR_getegid,
	__NR_getgroups, __NR_getresuid, __NR_getresgid,
	__NR_getpgrp, __NR_getpgid, __NR_getpid, __NR_getppid,
	__NR_setpgid,
	__NR_kill, __NR_tgkill, __NR_tkill,
	__NR_rt_sigsuspend, __NR_rt_sigtimedwait,
	__NR_eventfd, __NR_eventfd2,
	__NR_epoll_create, __NR_epoll_create1,
	__NR_epoll_ctl, __NR_epoll_wait, __NR_epoll_pwait,
	__NR_timerfd_create, __NR_timerfd_settime, __NR_timerfd_gettime,
	__NR_signalfd, __NR_signalfd4,
	__NR_getsockopt, __NR_setsockopt,
	__NR_getpeername, __NR_getsockname,
	__NR_sendfile, __NR_splice, __NR_vmsplice,
	__NR_sendmmsg, __NR_recvmmsg,
	__NR_preadv, __NR_preadv2, __NR_pwritev, __NR_pwritev2,
	__NR_readahead, __NR_memfd_create,
	-1
};

static const int rpath_syscalls[] = {
	__NR_open, __NR_openat, __NR_openat2,
	__NR_stat, __NR_statx, __NR_lstat, __NR_newfstatat,
	__NR_readlink, __NR_readlinkat,
	__NR_getdents, __NR_getdents64,
	__NR_access, __NR_faccessat, __NR_faccessat2,
	__NR_getcwd,
	__NR_chdir, __NR_fchdir,
	__NR_statfs, __NR_fstatfs,
	-1
};

static const int getpw_syscalls[] = {
	/* no getpwnam/getpwuid syscalls on Linux; lookups go through
	 * openat/read on /etc/passwd, covered by rpath+stdio */
	-1
};

static const int tty_syscalls[] = {
	__NR_ioctl,
	-1
};

static const int wpath_syscalls[] = {
	__NR_rename, __NR_renameat, __NR_renameat2,
	__NR_unlink, __NR_unlinkat,
	__NR_mkdir, __NR_mkdirat,
	__NR_rmdir,
	__NR_link, __NR_linkat,
	__NR_symlink, __NR_symlinkat,
	__NR_chmod, __NR_fchmod, __NR_fchmodat,
	__NR_chown, __NR_fchown, __NR_fchownat, __NR_lchown,
	__NR_utime, __NR_utimes, __NR_utimensat, __NR_futimesat,
	__NR_truncate, __NR_ftruncate,
	__NR_mknod, __NR_mknodat,
	__NR_flock,
	__NR_fallocate, __NR_fadvise64,
	__NR_sync_file_range, __NR_copy_file_range,
	__NR_sync, __NR_syncfs,
	__NR_setxattr, __NR_lsetxattr, __NR_fsetxattr,
	__NR_removexattr, __NR_lremovexattr, __NR_fremovexattr,
	-1
};

static const int id_syscalls[] = {
	__NR_setuid, __NR_setgid, __NR_setreuid, __NR_setregid,
	__NR_setresuid, __NR_setresgid, __NR_setgroups,
	-1
};

static const int exec_syscalls[] = {
	__NR_execve, __NR_execveat,
	__NR_clone, __NR_clone3, __NR_fork, __NR_vfork,
	__NR_wait4, __NR_waitid,
	__NR_pipe, __NR_pipe2,
	__NR_dup, __NR_dup2, __NR_dup3,
	__NR_fcntl,
	-1
};

static const struct {
	const char *name;
	const int *nr;
} promises[] = {
	{ "stdio", stdio_syscalls },
	{ "rpath", rpath_syscalls },
	{ "getpw", getpw_syscalls },
	{ "tty",   tty_syscalls   },
	{ "wpath", wpath_syscalls },
	{ "id",    id_syscalls    },
	{ "exec",  exec_syscalls  },
	{ NULL,    NULL           },
};

#define PTRS_MAX_FILTER 1024

static int
append(struct sock_filter *f, int *n, const int *nr, int max)
{
	int i;

	for (i = 0; nr[i] != -1; i++) {
		if (*n + 2 > max) {
			errno = E2BIG;
			return -1;
		}
		f[*n] = (struct sock_filter){
		    .code = BPF_JMP | BPF_JEQ | BPF_K,
		    .jt = 0, .jf = 1, .k = nr[i] };
		(*n)++;
		f[*n] = (struct sock_filter){
		    .code = BPF_RET | BPF_K,
		    .k = SECCOMP_RET_ALLOW };
		(*n)++;
	}
	return 0;
}

int
pledge(const char *promises_str, const char *execpromises)
{
	struct sock_filter f[1024];
	struct sock_fprog prog = { .len = 0, .filter = f };
	char *copy, *tok, *save;
	int n = 0, i, found;

	if (execpromises != NULL && *execpromises != '\0') {
		errno = EINVAL;
		return -1;
	}

	if (promises_str == NULL) {
		f[n++] = (struct sock_filter){
		    .code = BPF_LD | BPF_W | BPF_ABS,
		    .k = offsetof(struct seccomp_data, arch) };
		f[n++] = (struct sock_filter){
		    .code = BPF_JMP | BPF_JEQ | BPF_K,
		    .jt = 1, .jf = 0, .k = AUDIT_ARCH_X86_64 };
		f[n++] = (struct sock_filter){
		    .code = BPF_RET | BPF_K,
		    .k = SECCOMP_RET_KILL_PROCESS };
		f[n++] = (struct sock_filter){
		    .code = BPF_LD | BPF_W | BPF_ABS,
		    .k = offsetof(struct seccomp_data, nr) };
		f[n++] = (struct sock_filter){
		    .code = BPF_JMP | BPF_JEQ | BPF_K,
		    .jt = 0, .jf = 1, .k = __NR_exit };
		f[n++] = (struct sock_filter){
		    .code = BPF_RET | BPF_K,
		    .k = SECCOMP_RET_ALLOW };
		f[n++] = (struct sock_filter){
		    .code = BPF_JMP | BPF_JEQ | BPF_K,
		    .jt = 0, .jf = 1, .k = __NR_exit_group };
		f[n++] = (struct sock_filter){
		    .code = BPF_RET | BPF_K,
		    .k = SECCOMP_RET_ALLOW };
		f[n++] = (struct sock_filter){
		    .code = BPF_RET | BPF_K,
		    .k = SECCOMP_RET_KILL_PROCESS };
		goto install;
	}

	f[n++] = (struct sock_filter){
	    .code = BPF_LD | BPF_W | BPF_ABS,
	    .k = offsetof(struct seccomp_data, arch) };
	f[n++] = (struct sock_filter){
	    .code = BPF_JMP | BPF_JEQ | BPF_K,
	    .jt = 1, .jf = 0, .k = AUDIT_ARCH_X86_64 };
	f[n++] = (struct sock_filter){
	    .code = BPF_RET | BPF_K,
	    .k = SECCOMP_RET_KILL_PROCESS };
	f[n++] = (struct sock_filter){
	    .code = BPF_LD | BPF_W | BPF_ABS,
	    .k = offsetof(struct seccomp_data, nr) };

	if (append(f, &n, common_syscalls, PTRS_MAX_FILTER) < 0)
		return -1;

	copy = strdup(promises_str);
	if (copy == NULL)
		return -1;
	for (tok = strtok_r(copy, " ", &save); tok;
	    tok = strtok_r(NULL, " ", &save)) {
		found = 0;
		for (i = 0; promises[i].name; i++) {
			if (strcmp(promises[i].name, tok) == 0) {
				if (append(f, &n, promises[i].nr,
				    PTRS_MAX_FILTER) < 0) {
					free(copy);
					return -1;
				}
				found = 1;
				break;
			}
		}
		if (!found) {
			free(copy);
			errno = EINVAL;
			return -1;
		}
	}
	free(copy);

	f[n++] = (struct sock_filter){
	    .code = BPF_RET | BPF_K,
	    .k = SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA) };

install:
	prog.len = n;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		return -1;
	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == -1)
		return -1;
	return 0;
}