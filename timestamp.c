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
 * Linux equivalent of OpenBSD's TIOCSETVERAUTH / TIOCCHKVERAUTH.
 * Timestamp files in /run/doas, dual-clock expiry. No upstream code.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "timestamp.h"

#define TIMESTAMP_DIR "/run/doas"
#define TIMEOUT 300

static int
open_dir(void)
{
	int fd;

	fd = open(TIMESTAMP_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (fd != -1)
		return fd;
	if (errno != ENOENT)
		return -1;
	if (mkdir(TIMESTAMP_DIR, 0700) == -1 && errno != EEXIST)
		return -1;
	if (chown(TIMESTAMP_DIR, 0, 0) == -1 && errno != EPERM)
		return -1;
	return open(TIMESTAMP_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
}

static void
timestamp_path(char *buf, size_t len, uid_t uid)
{
	snprintf(buf, len, "%u", (unsigned)uid);
}

void
timestamp_set(uid_t uid)
{
	struct timespec ts[2];
	char path[32];
	int dirfd, fd;

	dirfd = open_dir();
	if (dirfd == -1)
		return;
	timestamp_path(path, sizeof(path), uid);
	fd = openat(dirfd, path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0);
	close(dirfd);
	if (fd == -1)
		return;

	if (clock_gettime(CLOCK_BOOTTIME, &ts[0]) == 0 &&
	    clock_gettime(CLOCK_REALTIME, &ts[1]) == 0) {
		ts[0].tv_sec += TIMEOUT;
		ts[1].tv_sec += TIMEOUT;
		futimens(fd, ts);
	}
	close(fd);
}

int
timestamp_check(uid_t uid)
{
	struct timespec now[2];
	struct stat st;
	char path[32];
	int dirfd, fd, valid = 0;

	dirfd = open_dir();
	if (dirfd == -1)
		return 0;
	timestamp_path(path, sizeof(path), uid);
	fd = openat(dirfd, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	close(dirfd);
	if (fd == -1)
		return 0;

	if (fstat(fd, &st) == 0 &&
	    S_ISREG(st.st_mode) &&
	    st.st_uid == 0 &&
	    (st.st_mode & 07777) == 0 &&
	    clock_gettime(CLOCK_BOOTTIME, &now[0]) == 0 &&
	    clock_gettime(CLOCK_REALTIME, &now[1]) == 0 &&
	    st.st_atim.tv_sec > now[0].tv_sec &&
	    st.st_atim.tv_sec - TIMEOUT <= now[0].tv_sec &&
	    st.st_atim.tv_sec < now[0].tv_sec + 2 * TIMEOUT &&
	    st.st_mtim.tv_sec > now[1].tv_sec &&
	    st.st_mtim.tv_sec < now[1].tv_sec + 2 * TIMEOUT)
		valid = 1;

	close(fd);
	return valid;
}

void
timestamp_clear(uid_t uid)
{
	char path[32];
	int dirfd;

	dirfd = open_dir();
	if (dirfd == -1)
		return;
	timestamp_path(path, sizeof(path), uid);
	unlinkat(dirfd, path, 0);
	close(dirfd);
}
