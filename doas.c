/* $OpenBSD: doas.c,v 1.100 2026/09/26 15:00:42 deraadt Exp $ */
/*
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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
 * Ported to Linux by realvolk. Changes from upstream doas.c 1.100:
 * PAM auth replaces BSD auth, setusercontext replaced by
 * setresgid/initgroups/setresuid, login.conf paths removed, pledge
 * calls routed through compat/pledge.c, unveil removed.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <limits.h>
#include <getopt.h>
#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <bsd/unistd.h>
#include <bsd/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>

#include "doas.h"
#include "pledge.h"
#include "timestamp.h"
#include "unveil.h"

#ifndef DOAS_CONF
#define DOAS_CONF "/etc/doas.conf"
#endif

static const struct option longopts[] = {
	{ "config",          required_argument, NULL, 'C' },
	{ "clear",           no_argument,       NULL, 'L' },
	{ "non-interactive", no_argument,       NULL, 'n' },
	{ "shell",           no_argument,       NULL, 's' },
	{ "user",            required_argument, NULL, 'u' },
	{ "unveil",          required_argument, NULL, 'U' },
	{ "pledge",          required_argument, NULL, 'P' },
	{ "version",         no_argument,       NULL, 'v' },
	{ "help",            no_argument,       NULL, 'h' },
	{ NULL, 0, NULL, 0 },
};

static void __dead
usage(void)
{
	fprintf(stderr, "usage: doas [-Lnsv] [-C config] [-u user]"
	    " [-U path] [-P promise] command [arg ...]\n");
	exit(1);
}

static int
parseuid(const char *s, uid_t *uid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*uid = pw->pw_uid;
		if (*uid == (uid_t)-1)
			return -1;
		return 0;
	}
	*uid = strtonum(s, 0, UINT_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
uidcheck(const char *s, uid_t desired)
{
	uid_t uid;

	if (parseuid(s, &uid) != 0)
		return -1;
	if (uid != desired)
		return -1;
	return 0;
}

static int
parsegid(const char *s, gid_t *gid)
{
	struct group *gr;
	const char *errstr;

	if ((gr = getgrnam(s)) != NULL) {
		*gid = gr->gr_gid;
		if (*gid == (gid_t)-1)
			return -1;
		return 0;
	}
	*gid = strtonum(s, 0, UINT_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
match(uid_t uid, gid_t *groups, int ngroups, uid_t target, const char *cmd,
    const char **cmdargs, struct rule *r)
{
	int i;

	if (r->ident[0] == ':') {
		gid_t rgid;
		if (parsegid(r->ident + 1, &rgid) == -1)
			return 0;
		for (i = 0; i < ngroups; i++) {
			if (rgid == groups[i])
				break;
		}
		if (i == ngroups)
			return 0;
	} else {
		if (uidcheck(r->ident, uid) != 0)
			return 0;
	}
	if (r->target && uidcheck(r->target, target) != 0)
		return 0;
	if (r->cmd) {
		if (strcmp(r->cmd, cmd))
			return 0;
		if (r->cmdargs) {
			/* if arguments were given, they should match explicitly */
			for (i = 0; r->cmdargs[i]; i++) {
				if (!cmdargs[i])
					return 0;
				if (strcmp(r->cmdargs[i], cmdargs[i]))
					return 0;
			}
			if (cmdargs[i])
				return 0;
		}
	}
	return 1;
}

static int
permit(uid_t uid, gid_t *groups, int ngroups, const struct rule **lastr,
    uid_t target, const char *cmd, const char **cmdargs)
{
	size_t i;

	*lastr = NULL;
	for (i = 0; i < nrules; i++) {
		if (match(uid, groups, ngroups, target, cmd,
		    cmdargs, rules[i]))
			*lastr = rules[i];
	}
	if (!*lastr)
		return -1;
	if ((*lastr)->action == PERMIT)
		return 0;
	return -1;
}

static void
parseconfig(const char *filename, int checkperms)
{
	extern FILE *yyfp;
	extern int yyparse(void);
	struct stat sb;

	yyfp = fopen(filename, "r");
	if (!yyfp)
		err(1, checkperms ? "doas is not enabled, %s" :
		    "could not open config file %s", filename);

	if (checkperms) {
		if (fstat(fileno(yyfp), &sb) != 0)
			err(1, "fstat(\"%s\")", filename);
		if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
			errx(1, "%s is writable by group or other", filename);
		if (sb.st_uid != 0)
			errx(1, "%s is not owned by root", filename);
	}

	yyparse();
	fclose(yyfp);
	if (parse_error)
		exit(1);
}

static void __dead
checkconfig(const char *confpath, int argc, char **argv,
    uid_t uid, gid_t *groups, int ngroups, uid_t target)
{
	const struct rule *rule;
	int rv;

	if (setresuid(uid, uid, uid) != 0)
		err(1, "setresuid");
	if (pledge("stdio rpath getpw", NULL) == -1)
		err(1, "pledge");
	parseconfig(confpath, 0);
	if (!argc)
		exit(0);
	rv = permit(uid, groups, ngroups, &rule, target, argv[0],
 	    (const char **)argv + 1);
	if (rv == 0) {
		printf("permit%s\n", (rule->options & NOPASS) ? " nopass" : "");
		exit(0);
	} else {
		printf("deny\n");
		exit(1);
	}
}

static const char *
prescan_config(int argc, char **argv)
{
	int i, j;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--") == 0)
			break;
		if (strncmp(a, "--config=", 9) == 0)
			return a + 9;
		if (strcmp(a, "--config") == 0 && i + 1 < argc)
			return argv[++i];
		if (a[0] != '-')
			break;          /* first non-option: stop (posix) */
		if (a[1] == '-')
			continue;
		for (j = 1; a[j]; j++) {
			if (a[j] == 'C') {
				if (a[j + 1])
					return &a[j + 1];
				if (i + 1 < argc)
					return argv[++i];
				return NULL;
			}
			if (a[j] == 'u') {
				if (!a[j + 1])
					i++;
				break;
			}
		}
	}
	return NULL;
}

int
main(int argc, char **argv)
{
	const char *safepath = SAFE_PATH;
	const char *confpath = NULL;
	char *shargv[] = { NULL, NULL };
	char *sh;
	const char *p;
	const char *cmd;
	char cmdline[LINE_MAX];
	char mypwbuf[_PW_BUF_LEN], targpwbuf[_PW_BUF_LEN];
	struct passwd mypwstore, targpwstore;
	struct passwd *mypw, *targpw;
	const struct rule *rule;
	uid_t uid;
	uid_t target = 0;
	gid_t groups[NGROUPS_MAX + 1];
	int ngroups;
	int i, ch, rv;
	int sflag = 0;
	int nflag = 0;
	char cwdpath[PATH_MAX];
	const char *cwd;
	char **envp;

	const char *preconf;
	const char *optstring;
	const char **unveil_paths = NULL;
	size_t unveil_count = 0;
	const char **pledge_promises = NULL;
	size_t pledge_count = 0;
	char promise_buf[512];

	setprogname("doas");

	closefrom(STDERR_FILENO + 1);

	uid = getuid();

	preconf = prescan_config(argc, argv);
	if (!preconf) {
		/* Normal mode: parse config before getopt to learn
		 * getopt_mode. rules[] and getopt_mode are set. */
		parseconfig(DOAS_CONF, 1);
	}

	if (preconf || getopt_mode == GETOPT_POSIX)
		optstring = "+C:Lnsu:U:P:vh";
	else
		optstring = "C:Lnsu:U:P:vh";

	opterr = 0;
	while ((ch = getopt_long(argc, argv, optstring, longopts,
	    NULL)) != -1) {
		switch (ch) {
		case 'C':
			confpath = optarg;
			break;
		case 'L':
			timestamp_clear(uid);
			exit(0);
		case 'u':
			if (parseuid(optarg, &target) != 0)
				errx(1, "unknown user");
			break;
		case 'n':
			nflag = 1;
			break;
		case 's':
			sflag = 1;
			break;
		case 'U':
			unveil_paths = reallocarray(unveil_paths,
			    unveil_count + 1, sizeof(*unveil_paths));
			if (!unveil_paths)
				err(1, NULL);
			unveil_paths[unveil_count++] = optarg;
			break;
		case 'P':
			pledge_promises = reallocarray(pledge_promises,
			    pledge_count + 1, sizeof(*pledge_promises));
			if (!pledge_promises)
				err(1, NULL);
			pledge_promises[pledge_count++] = optarg;
			break;
		case 'v':
			printf("doas-linux 0.1.0 (OpenBSD doas.c 1.100)\n");
			exit(0);
		case 'h':
			usage();
			break;
		default:
			usage();
			break;
		}
	}
	argv += optind;
	argc -= optind;

	if (confpath) {
		if (sflag)
			usage();
	} else if ((!sflag && !argc) || (sflag && argc))
		usage();

	rv = getpwuid_r(uid, &mypwstore, mypwbuf, sizeof(mypwbuf), &mypw);
	if (rv != 0)
		err(1, "getpwuid_r failed");
	if (mypw == NULL)
		errx(1, "no passwd entry for self");
	ngroups = getgroups(NGROUPS_MAX, groups);
	if (ngroups == -1)
		err(1, "can't get groups");
	groups[ngroups++] = getgid();

	if (sflag) {
		sh = getenv("SHELL");
		if (sh == NULL || *sh == '\0') {
			shargv[0] = mypw->pw_shell;
		} else
			shargv[0] = sh;
		argv = shargv;
		argc = 1;
	}

	if (confpath) {
		if (pledge("stdio rpath getpw id", NULL) == -1)
			err(1, "pledge");
		checkconfig(confpath, argc, argv, uid, groups, ngroups,
		    target);
		exit(1);	/* fail safe */
	}

	if (nrules == 0)
		parseconfig(DOAS_CONF, 1);

	if (geteuid())
		errx(1, "not installed setuid");

	/* parseconfig(DOAS_CONF, 1) was already called above */

	/* cmdline is used only for logging, no need to abort on truncate */
	(void)strlcpy(cmdline, argv[0], sizeof(cmdline));
	for (i = 1; i < argc; i++) {
		if (strlcat(cmdline, " ", sizeof(cmdline)) >= sizeof(cmdline))
			break;
		if (strlcat(cmdline, argv[i], sizeof(cmdline)) >= sizeof(cmdline))
			break;
	}

	cmd = argv[0];
	rv = permit(uid, groups, ngroups, &rule, target, cmd,
	    (const char **)argv + 1);
	if (rv != 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "command not permitted for %s: %s", mypw->pw_name, cmdline);
		errc(1, EPERM, NULL);
	}

	if (!(rule->options & NOPASS)) {
		if (nflag)
			errx(1, "Authentication required");
	}

	if ((p = getenv("PATH")) != NULL)
		formerpath = strdup(p);
	if (formerpath == NULL)
		formerpath = "";

	if (rule->cmd) {
		if (setenv("PATH", safepath, 1) == -1)
			err(1, "failed to set PATH '%s'", safepath);
	}

	rv = getpwuid_r(target, &targpwstore, targpwbuf, sizeof(targpwbuf), &targpw);
	if (rv != 0)
		err(1, "getpwuid_r failed");
	if (targpw == NULL)
		errx(1, "no passwd entry for target");

	if (!(rule->options & NOPASS)) {
		int authed = 0;

		if ((rule->options & PERSIST) && timestamp_check(uid))
			authed = 1;

		if (!authed) {
			pamauth(targpw->pw_name, mypw->pw_name, !nflag,
			    rule->options & NOPASS, rule->options & PERSIST);
			if (rule->options & PERSIST)
				timestamp_set(uid);
		}
	}

	if (unveil_count > 0) {
		unveil_core_paths();
		if (cmd[0] == '/') {
			if (unveil(cmd, "rx") == -1)
				warn("unveil %s", cmd);
		} else {
			char *pathcopy = strdup(getenv("PATH") ? getenv("PATH") : "");
			char *tok, *save;
			int found = 0;

			if (pathcopy) {
				for (tok = strtok_r(pathcopy, ":", &save); tok;
				    tok = strtok_r(NULL, ":", &save)) {
					char buf[PATH_MAX];
					snprintf(buf, sizeof(buf), "%s/%s", tok, cmd);
					if (unveil(buf, "rx") == 0)
						found++;
				}
				free(pathcopy);
			}
			if (!found)
				warnx("unveil: no candidate for '%s' in PATH", cmd);
		}
		for (i = 0; i < (int)unveil_count; i++) {
			if (unveil(unveil_paths[i], "a") == -1) {
				if (errno == ENOSYS)
					break;
				err(1, "unveil %s", unveil_paths[i]);
			}
		}
	}

	if (pledge_count > 0) {
		strlcpy(promise_buf, "stdio rpath wpath getpw exec id",
		    sizeof(promise_buf));
		for (i = 0; i < (int)pledge_count; i++) {
			if (strlcat(promise_buf, " ", sizeof(promise_buf)) >=
			    sizeof(promise_buf))
				errx(1, "promise string too long");
			if (strlcat(promise_buf, pledge_promises[i],
			    sizeof(promise_buf)) >= sizeof(promise_buf))
				errx(1, "promise string too long");
		}
		if (pledge(promise_buf, NULL) == -1)
			err(1, "pledge");
	}

	if (setresgid(targpw->pw_gid, targpw->pw_gid, targpw->pw_gid) != 0)
		err(1, "setresgid");
	if (initgroups(targpw->pw_name, targpw->pw_gid) != 0)
		err(1, "initgroups");
	if (setresuid(target, target, target) != 0)
		err(1, "setresuid");

	if (getcwd(cwdpath, sizeof(cwdpath)) == NULL)
		cwd = "(failed)";
	else
		cwd = cwdpath;

	if (!(rule->options & NOLOG)) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "%s ran command %s as %s from %s",
		    mypw->pw_name, cmdline, targpw->pw_name, cwd);
	}

	envp = prepenv(rule, mypw, targpw);

	if (rule->cmd) {
		if (setenv("PATH", safepath, 1) == -1)
			err(1, "failed to set PATH '%s'", safepath);
	} else {
		if (setenv("PATH", formerpath, 1) == -1)
			err(1, "failed to set PATH '%s'", formerpath);
	}
	if (unveil_count > 0 && unveil_commit() == -1)
		err(1, "unveil_commit");
	execvpe(cmd, argv, envp);
fail:
	if (errno == ENOENT)
		errx(1, "%s: command not found", cmd);
	err(1, "%s", cmd);
}
