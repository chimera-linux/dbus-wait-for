# dbus-wait-for

This is a little command to help integrate D-Bus activation into service
managers and various scripts.

You run a program through it, and it waits for the program to register the
given name on the bus (session bus by default, but system bus can be used
as well, or even a custom address); once that has happened, it writes the
string `READY=1\n` on the given file descriptor.

Checking is done to ensure the registration originated in the program. See
below for possible caveats.

The readiness notification is made to be compatible with Dinit (and s6) in
mind, but it can work with anything implementing the simple protocol. The
file descriptor to write to can be given directly as a number, or the number
can be the value of a given environment variable.

A timeout can be specified (with 1-second granularity). The default timeout
is 1 minute, to match Dinit's default service readiness timeout.

## Invocation

An example invocation would be as such:

```
$ dbus-wait-for -n org.test.Server -f 4 my-command arg1 arg2 ... 4> ready.txt
```

This waits for `my-command` to register a name `org.test.Server` on the
default session bus and when it does so, writes the readiness message
on file descriptor 4. You will see `READY=1` in `ready.txt` once that
has happened.

## How it works

First, the program obtains a D-Bus connection. This is done early so that
we get the stuff prone to failure cases done early.

Afterwards, we fork. The parent tries to reap the child (by waiting for it)
and afterwards replaces itself with the requested program. That means once
the program has executed, service supervisors can monitor it normally.

As for the child, it will first become a session leader (`setsid`) and forks
again. This is done to create a process that is disconnected from the original
and is managed directly by PID 1 (daemonized). It will then terminate (so the
original parent can proceed).

The final child runs a D-Bus mainloop and listens on `NameOwnerChanged` signal
of the `org.freedesktop.DBus` interface/object. Once it receives the name that
was requested, it will obtain the process ID of its new owner by calling the
`GetConnectionUnixProcessID` method on the same object. Once that returns a
valid value and the necessary checks pass, it will do readiness notification
by writing on the file descriptor.

## Portability

The base program is portable and will work on any POSIX-compatible OS.
At the baseline, the name origin check is done by finding the PID of the
process that obtained the name and comparing it against the PID of the
program we've run.

This has a few possible drawbacks:

1) Since an exact PID check is done, if the program forks and registers the
   name in a child process, it will not be seen, and the readiness notification
   will never hpapen.
2) If the program dies and something else claims its PID and registers the name,
   it could result in a spurious readiness notification. This is a potential
   race but is most likely harmless, as the readiness check should be paired
   with a process supervisor for the actual service, which should see the
   crash.

### cgroups

This is implemented on Linux only. Using cgroups to do the check will mitigate
both scenarios, if applicable and enabled. Instead of checking the exact PID,
we can do a cgroups check provided the following:

1) The `dbus-wait-for` belongs to a control group.
2) A cgroups v2 filesystem is mounted, and the group the process belongs to
   is a v2 control group. Any v1 groups are ignored and no v1 checks are
   implemented.

If these are true, the cgroups check can be done in place of the PID check
if requested. A file descriptor to the control group is obtained early on
and retained for the check across forks. Then instead of comparing PIDs,
the control group's process list is scanned for the owner PID of the name
and if it's found, the check passes.

Note you probably only really want to do a cgroups-based check if you can
guarantee that the service has a group for itself, or if there is no chance
of name clashes between processes in the group.

## Building

You can build the project with Meson. The only dependencies are a C99 compiler
and `dbus-1` library (the low level library from freedesktop that comes with
the reference implementation).

You can also build the program manually, such as:

```
$ cc dbus-wait-for.c -O2 -g -Wall -Wextra $(pkg-config --libs --cflags dbus-1)
```
