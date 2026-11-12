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
 * Landlock-based implementation of OpenBSD's unveil(2). Rules are
 * inherited across execve; unlike OpenBSD, the executed command is
 * restricted by the caller's ruleset. Requires Linux 5.13+.
 */

#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <linux/landlock.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <string.h>

#include "unveil.h"

static int ruleset_fd = -1;
static int landlock_abi = -1;
static int rules_committed = 0;

static int
landlock_init(void)
{
	struct landlock_ruleset_attr attr = {
		.handled_access_fs =
		    LANDLOCK_ACCESS_FS_EXECUTE |
		    LANDLOCK_ACCESS_FS_READ_FILE |
		    LANDLOCK_ACCESS_FS_WRITE_FILE |
		    LANDLOCK_ACCESS_FS_REMOVE_FILE |
		    LANDLOCK_ACCESS_FS_REMOVE_DIR |
		    LANDLOCK_ACCESS_FS_MAKE_REG |
		    LANDLOCK_ACCESS_FS_MAKE_DIR |
		    LANDLOCK_ACCESS_FS_MAKE_SYM,
	};
	long r;

	r = syscall(__NR_landlock_create_ruleset, NULL, 0,
	    LANDLOCK_CREATE_RULESET_VERSION);
	if (r < 1) {
		landlock_abi = 0;
		return -1;
	}
	landlock_abi = (int)r;

	if (landlock_abi >= 2)
		attr.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
	if (landlock_abi >= 3)
		attr.handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;

	ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
	    sizeof(attr), 0);
	return ruleset_fd;
}

int
unveil(const char *path, const char *flags)
{
	struct landlock_path_beneath_attr pb;
	__u64 access = 0;
	const char *p;
	int fd, ret;

	if (rules_committed) {
		errno = EPERM;
		return -1;
	}
	if (ruleset_fd == -1 && landlock_init() < 0)
		return -1;

	for (p = flags; *p; p++) {
		switch (*p) {
		case 'r':
			access |= LANDLOCK_ACCESS_FS_READ_FILE;
			break;
		case 'w':
			access |= LANDLOCK_ACCESS_FS_WRITE_FILE;
			if (landlock_abi >= 3)
				access |= LANDLOCK_ACCESS_FS_TRUNCATE;
			break;
		case 'x':
			access |= LANDLOCK_ACCESS_FS_EXECUTE;
			break;
		case 'c':
			access |= LANDLOCK_ACCESS_FS_MAKE_REG;
			access |= LANDLOCK_ACCESS_FS_MAKE_DIR;
			access |= LANDLOCK_ACCESS_FS_MAKE_SYM;
			break;
		case 'd':
			access |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
			access |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
			break;
		case 'a':
			access |= LANDLOCK_ACCESS_FS_EXECUTE;
			access |= LANDLOCK_ACCESS_FS_READ_FILE;
			access |= LANDLOCK_ACCESS_FS_WRITE_FILE;
			access |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
			access |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
			access |= LANDLOCK_ACCESS_FS_MAKE_REG;
			access |= LANDLOCK_ACCESS_FS_MAKE_DIR;
			access |= LANDLOCK_ACCESS_FS_MAKE_SYM;
			if (landlock_abi >= 2)
				access |= LANDLOCK_ACCESS_FS_REFER;
			if (landlock_abi >= 3)
				access |= LANDLOCK_ACCESS_FS_TRUNCATE;
			break;
		default:
			errno = EINVAL;
			return -1;
		}
	}

	fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return -1;

	{
		struct stat st;
		if (fstat(fd, &st) == -1) {
			close(fd);
			return -1;
		}
		if (!S_ISDIR(st.st_mode)) {
			__u64 file_access = LANDLOCK_ACCESS_FS_EXECUTE |
			    LANDLOCK_ACCESS_FS_READ_FILE |
			    LANDLOCK_ACCESS_FS_WRITE_FILE;
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
			file_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
			access &= file_access;
		}
	}

	pb.allowed_access = access;
	pb.parent_fd = fd;
	ret = syscall(__NR_landlock_add_rule, ruleset_fd,
	    LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
	close(fd);
	return ret;
}

int
unveil_commit(void)
{
	int ret;

	if (rules_committed)
		return 0;
	if (ruleset_fd < 0) {
		errno = ENOSYS;
		return -1;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		return -1;
	ret = syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
	close(ruleset_fd);
	ruleset_fd = -1;
	rules_committed = 1;
	return ret;
}

int
unveil_core_paths(void)
{
	int added = 0;

	/* Best-effort. Errors are ignored; missing paths are skipped. */
#define U(p, f) do { if (unveil((p), (f)) == 0) added++; } while (0)
	U("/etc/ld.so.cache", "r");
	U("/etc/ld.so.conf", "r");
	U("/etc/ld.so.conf.d", "r");
	U("/etc/ld.so.preload", "r");
	U("/lib", "rx");
	U("/lib64", "rx");
	U("/usr/lib", "rx");
	U("/usr/lib64", "rx");
	U("/etc/passwd", "r");
	U("/etc/group", "r");
	U("/etc/nsswitch.conf", "r");
	U("/etc/localtime", "r");
	U("/etc/resolv.conf", "r");
	U("/etc/hosts", "r");
	U("/etc/ssl", "r");
	U("/etc/ca-certificates", "r");
	U("/etc/pki", "r");
	U("/usr/share/locale", "r");
	U("/usr/share/zoneinfo", "r");
	U("/dev/null", "rw");
	U("/dev/zero", "r");
	U("/dev/urandom", "r");
	U("/dev/random", "r");
	U("/dev/tty", "rw");
	U("/proc", "r");
	U("/sys", "r");
#undef U
	return added;
}