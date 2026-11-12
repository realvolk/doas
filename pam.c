/*
 * Copyright (c) 2015 Nathan Holstein <nathan.holstein@gmail.com>
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
 * Linux PAM backend for doas. Modeled on OpenDoas's pam.c (ISC,
 * Nathan Holstein), adapted to doas.c 1.100's auth flow and
 * AUTH_RETRIES loop.
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <bsd/readpassphrase.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include "doas.h"

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

#define PAM_SERVICE_NAME "doas"

static pam_handle_t *pamh = NULL;
static char doas_prompt[128];
static sig_atomic_t volatile caught_signal = 0;

static void
catchsig(int sig)
{
	caught_signal = sig;
}

static char *
pamprompt(const char *msg, int echo_on, int *ret)
{
	const char *prompt;
	char *pass, buf[PAM_MAX_RESP_SIZE];
	int flags = RPP_REQUIRE_TTY | (echo_on ? RPP_ECHO_ON : RPP_ECHO_OFF);

	if (strncmp(msg, "Password:", 9) == 0 &&
	    (msg[9] == '\0' || (msg[9] == ' ' && msg[10] == '\0')))
		prompt = doas_prompt;
	else
		prompt = msg;

	pass = readpassphrase(prompt, buf, sizeof(buf), flags);
	if (!pass)
		*ret = PAM_CONV_ERR;
	else if (!(pass = strdup(pass)))
		*ret = PAM_BUF_ERR;
	else
		*ret = PAM_SUCCESS;

	explicit_bzero(buf, sizeof(buf));
	return pass;
}

static int
pamconv(int nmsgs, const struct pam_message **msgs,
    struct pam_response **rsps, void *ptr)
{
	struct pam_response *rsp;
	int i, style;
	int ret;

	(void)ptr;

	if (!(rsp = calloc(nmsgs, sizeof(struct pam_response))))
		err(1, "could not allocate pam_response");

	for (i = 0; i < nmsgs; i++) {
		switch (style = msgs[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			rsp[i].resp = pamprompt(msgs[i]->msg,
			    style == PAM_PROMPT_ECHO_ON, &ret);
			if (ret != PAM_SUCCESS)
				goto fail;
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			if (fprintf(stderr, "%s\n", msgs[i]->msg) < 0)
				goto fail;
			break;
		default:
			errx(1, "invalid PAM msg_style %d", style);
		}
	}

	*rsps = rsp;
	return PAM_SUCCESS;

fail:
	for (i = 0; i < nmsgs; i++) {
		if (rsp[i].resp == NULL)
			continue;
		switch (msgs[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			explicit_bzero(rsp[i].resp, strlen(rsp[i].resp));
			free(rsp[i].resp);
		}
		rsp[i].resp = NULL;
	}
	free(rsp);
	return PAM_CONV_ERR;
}

static void
pamcleanup(int ret, int sess, int cred)
{
	if (sess) {
		ret = pam_close_session(pamh, 0);
		if (ret != PAM_SUCCESS)
			errx(1, "pam_close_session: %s",
			    pam_strerror(pamh, ret));
	}
	if (cred) {
		ret = pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);
		if (ret != PAM_SUCCESS)
			warn("pam_setcred(PAM_DELETE_CRED): %s",
			    pam_strerror(pamh, ret));
	}
	pam_end(pamh, ret);
}

static void
watchsession(pid_t child, int sess, int cred)
{
	sigset_t sigs;
	struct sigaction act, oldact = { 0 }, oldint = { 0 };
	int status = 1;

	sigfillset(&sigs);
	if (sigprocmask(SIG_BLOCK, &sigs, NULL)) {
		warn("failed to block signals");
		caught_signal = 1;
		goto close;
	}

	act.sa_handler = catchsig;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigemptyset(&sigs);
	if (sigaddset(&sigs, SIGTERM) ||
	    sigaddset(&sigs, SIGINT) ||
	    sigaction(SIGTERM, &act, &oldact) ||
	    sigaction(SIGINT, &act, &oldint) ||
	    sigprocmask(SIG_UNBLOCK, &sigs, NULL)) {
		warn("failed to set signal handler");
		caught_signal = 1;
		goto close;
	}

	if (waitpid(child, &status, 0) != -1) {
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "%s%s\n",
			    strsignal(WTERMSIG(status)),
			    WCOREDUMP(status) ? " (core dumped)" : "");
			status = WTERMSIG(status) + 128;
		} else
			status = WEXITSTATUS(status);
	} else if (caught_signal)
		status = caught_signal + 128;
	else
		status = 1;

close:
	if (caught_signal && child != (pid_t)-1) {
		fprintf(stderr, "\nSession terminated, killing shell\n");
		kill(child, SIGTERM);
	}
	pamcleanup(PAM_SUCCESS, sess, cred);
	if (caught_signal) {
		if (child != (pid_t)-1) {
			sleep(2);
			kill(child, SIGKILL);
			fprintf(stderr, " ...killed.\n");
		}
		sigaction(SIGTERM, &oldact, NULL);
		sigaction(SIGINT, &oldint, NULL);
		kill(getpid(), caught_signal);
	}
	exit(status);
}

void
pamauth(const char *user, const char *myname, int interactive, int nopass,
    int persist)
{
	static const struct pam_conv conv = {
		.conv = pamconv,
		.appdata_ptr = NULL,
	};
	const char *ttydev;
	pid_t child;
	int ret, sess = 0, cred = 0, i;

	(void)persist;

	if (!user || !myname)
		errx(1, "Authentication failed");

	ret = pam_start(PAM_SERVICE_NAME, myname, &conv, &pamh);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_start failed");

	ret = pam_set_item(pamh, PAM_RUSER, myname);
	if (ret != PAM_SUCCESS)
		warn("pam_set_item(PAM_RUSER): %s", pam_strerror(pamh, ret));

	if (isatty(0) && (ttydev = ttyname(0)) != NULL) {
		if (strncmp(ttydev, "/dev/", 5) == 0)
			ttydev += 5;
		ret = pam_set_item(pamh, PAM_TTY, ttydev);
		if (ret != PAM_SUCCESS)
			warn("pam_set_item(PAM_TTY): %s",
			    pam_strerror(pamh, ret));
	}

	if (!nopass) {
		char host[HOST_NAME_MAX + 1];

		if (!interactive)
			errx(1, "Authentication required");

		if (gethostname(host, sizeof(host)))
			snprintf(host, sizeof(host), "?");
		snprintf(doas_prompt, sizeof(doas_prompt),
		    "\rdoas (%.32s@%.32s) password: ", myname, host);

		for (i = 0; i < AUTH_RETRIES; i++) {
			ret = pam_authenticate(pamh, 0);
			if (ret == PAM_SUCCESS)
				break;
			if (ret != PAM_AUTH_ERR && ret != PAM_USER_UNKNOWN &&
			    ret != PAM_MAXTRIES) {
				pamcleanup(ret, sess, cred);
				errx(1, "pam_authenticate: %s",
				    pam_strerror(pamh, ret));
			}
		}
		if (ret != PAM_SUCCESS) {
			pamcleanup(ret, sess, cred);
			syslog(LOG_AUTHPRIV | LOG_NOTICE,
			    "failed auth for %s", myname);
			errx(1, "Authentication failed");
		}
	}

	ret = pam_acct_mgmt(pamh, 0);
	if (ret == PAM_NEW_AUTHTOK_REQD)
		ret = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
	if (ret != PAM_SUCCESS) {
		pamcleanup(ret, sess, cred);
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "failed auth for %s", myname);
		errx(1, "Authentication failed");
	}

	ret = pam_set_item(pamh, PAM_USER, user);
	if (ret != PAM_SUCCESS)
		warn("pam_set_item(PAM_USER): %s", pam_strerror(pamh, ret));

	ret = pam_setcred(pamh, PAM_REINITIALIZE_CRED);
	if (ret == PAM_SUCCESS)
		cred = 1;
	else
		warn("pam_setcred: %s", pam_strerror(pamh, ret));

	ret = pam_open_session(pamh, 0);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_open_session: %s", pam_strerror(pamh, ret));
	sess = 1;

	if ((child = fork()) == -1) {
		pamcleanup(PAM_ABORT, sess, cred);
		err(1, "fork");
	}

	if (child == 0)
		return;

	watchsession(child, sess, cred);
}
