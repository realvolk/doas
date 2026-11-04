# doas-linux

Linux port of OpenBSD doas(1). Tracks upstream doas.c 1.100.

## Build

Needs libbsd and PAM.

    ./configure
    make
    make install

configure flags: --prefix --sysconfdir --bindir --mandir --with-safepath

## PAM

No config shipped. Write /etc/pam.d/doas yourself:

    cp /etc/pam.d/sudo /etc/pam.d/doas

## Usage

    doas cmd
    doas -- cmd arg

-- ends option parsing. Use it when the command has flags:

    doas -- /usr/bin/pacman -Qi bash

## Argument parsing

By default, doas stops parsing options at the first non-option word.
`doas /usr/bin/pacman -Qi bash` works: `pacman` is the first non-option,
parsing stops, `-Qi bash` is the command's arguments. This is POSIX
mode, and it's what sudo and OpenBSD doas do.

GNU getopt does the opposite: it scans the whole line and treats every
`-flag` as doas's own, even after the command. `doas /usr/bin/pacman
-Qi bash` in GNU mode fails with `invalid option -- 'Q'`, because doas
tries to parse `-Q` as its own flag. That's why the `--` escape exists,
and why it's needed by default.

To switch to GNU mode (sudo users won't need `--`):

    set getopt = permute

in /etc/doas.conf. The default is `posix`. The directive is documented
in doas.conf(5).

## Filesystem sandbox (Landlock)

The sandbox is off by default. Without `-U`, the command sees the
whole filesystem, same as stock doas and sudo.

To enable it for one invocation, pass `-U path`. May be repeated.

    doas -U /etc/shadow -- /usr/bin/cat /etc/shadow

With at least one `-U`, the command sees a core set (libc,
/etc/passwd, /etc/group, /etc/nsswitch.conf, /etc/ssl, /dev/null,
/dev/urandom, /proc, /sys) plus the binary itself plus each `-U`
path. Anything else is blocked.

`-U` means full access: read, write, create, delete, rename. For a
regular file, the create/delete rights are dropped (the kernel
rejects them on non-directories).

Sandboxed pacman:

    alias pkg='doas -U /var/lib/pacman -U /var/cache/pacman \
        -U /etc/pacman.conf -U /etc/pacman.d -U /var/log \
        -U /var/tmp -P tty -- /usr/bin/pacman'

Without `-U`, `doas -- /usr/bin/pacman -Syu` works like
`sudo pacman -Syu`. With the alias, pacman is restricted to its own
paths.

If Landlock is unavailable (kernel < 5.13), `-U` prints a warning to
stderr once and the sandbox is skipped.

## Syscall filter (seccomp)

The filter is off by default. Without `-P`, the command has the full
syscall interface, same as stock doas and sudo.

To enable it for one invocation, pass `-P promise`. May be repeated.
The base promise set is `stdio rpath wpath getpw exec id`. Unlisted
syscalls return EPERM; programs fall back or error, they don't die.

When the filter is enabled, `ioctl` is not in the base promise set.
Interactive programs (nano, vim, htop) need `-P tty`:

    doas -P tty -- /usr/bin/nano /etc/hosts

Without it, `ioctl` returns EPERM. This blocks TIOCSTI tty character
injection, where an unprivileged process injects characters into the
tty input queue that the next reader (usually root) consumes. OpenDoas
#106, open since 2022.

To add promises for one invocation, pass `-P promise`. May be repeated.

    doas -P inet -P dns -- /usr/bin/curl -sI https://example.com

The syscall table is hand-maintained. It's tuned for the programs
under Tested. To find a missing syscall:

    sudo strace -f -u "$(whoami)" doas cmd

sudo is needed: strace disables setuid on the tracee. `grep -E '= -1
EPERM'` on the trace log shows which syscalls are blocked, and the
last one before a failure is the one to add to compat/pledge.c.

## Differences from OpenBSD

- PAM, not BSD auth. -a removed. Service name "doas".
- No login.conf. PATH at compile time. /usr/local before /usr,
  Linux convention. See --with-safepath.
- Rule ordering: last match wins. A later permit without persist
  drops persist from an earlier permit persist.
- setusercontext -> setresgid, initgroups, setresuid.
- persist: timestamp files in /run/doas, dual-clock expiry.
  atime renders as 1970 in stat. Correct.
- pledge: seccomp, exposed as -P flag. Off by default; opt in by
  passing at least one -P. ioctl moved to a tty promise. TIOCSTI
  blocked when the filter is enabled and -P tty isn't passed.
- unveil: Landlock, exposed as -U flag. Off by default; opt in by
  passing at least one -U. Rules are inherited across execve, so
  the executed command is sandboxed. OpenBSD's doas leaves the
  child unveiled either way.
- set getopt = permute: opt-in GNU-style argument parsing.
  Default is posix (matches sudo and OpenBSD doas). See
  doas.conf(5).
- Line continuation in doas.conf works. OpenDoas #137.

## Tested

Artix Linux, dinit, x86_64.

- doas -C, id, -L, -n, -u nobody, -v
- persist, two calls <5min: second skips PAM
- /run/doas created root:root, not root:user
- sh -c, exit status, $HOME/$USER, keepenv, setenv
- pacman -Qi, -Syu, both with and without -U sandbox
- sandbox default off: cat /etc/shadow works
- sandbox -U: cat /etc/shadow blocked without -U, allowed with -U /etc/shadow
- seccomp default off: nano works without -P
- seccomp -P: nano blocked without -P tty, works with -P tty
- ls, cat, printenv, nano, git, dinitctl
- sleep, Ctrl-C during a running command (SIGINT cleanup)
- getopt posix and permute modes
- doas.conf line continuation
- config permission check: 666, 664, non-root-owned refused

## Not tested

- Programs not listed. vim, systemctl may EPERM.
- PAM modules beyond pam_unix.
- syslog. No syslogd running.
- Persist across reboot.
- Multi-user. Timestamp keyed on uid only.
- Landlock on kernels < 5.13 (sandbox is skipped).

## Prior art

- OpenDoas (Duncaen/OpenDoas): Linux, dormant since 2022-02.
  doas.c 1.52.
- thejessesmith/doas: BSD/macOS/illumos, active. doas.c 1.57.

Upstream 1.100 is 44 revisions ahead of both.

## OpenDoas issues closed

- #47 timestamp directory group
- #60 make clean needs config.mk
- #82 multiple auth tries
- #87 -v/--version
- #106 TIOCSTI tty injection
- #117 safepath ordering
- #128 prefer system PATH
- #129 --gid-max sets UID_MAX (not present)
- #137 doas.conf line continuation

## License

ISC. See file headers.