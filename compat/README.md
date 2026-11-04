# compat/

Linux shims for OpenBSD primitives that Linux doesn't have.

pledge.c / pledge.h: seccomp. The syscall table is hand-maintained
and does not match OpenBSD's promises 1:1. Unlisted syscalls return
EPERM, not SIGSYS. The -P flag adds promises per-invocation.

unveil.c / unveil.h: Landlock. Needs Linux 5.13+; 6.2+ for TRUNCATE
and REFER. Rules are inherited across execve, so the executed command
is sandboxed. The -U flag adds paths per-invocation. Files get
EXECUTE|READ_FILE|WRITE_FILE|TRUNCATE; directories get the full set.
Landlock rejects directory-only rights on regular files with EINVAL,
so the mask is reduced by fstat/S_ISDIR.

Both are exposed as flags (-P, -U) rather than baked into the source,
because Linux has no equivalent of OpenBSD's per-process pledge/unveil
that clears on exec.

If a platform provides these natively, move the shim out and drop
-Icompat.