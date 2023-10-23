/*
 * A wrapper for implementation of D-Bus readiness notification.
 *
 * The wrapper utilizes double-forking; it first forks, detaches child from
 * the terminal, forks again, and exits the sub-parent (daemonizes).
 *
 * However, the first parent does not just exit; it first reaps the original
 * child and execs the given command (with the given arguments). The daemon
 * child then waits until the given bus name is taken, and once that happens,
 * writes on the readiness descriptor.
 *
 * The readiness descriptor can be specified either as a number or as an
 * environment variable having a number as its value.
 *
 * Before writing on the descriptor, we need to make sure the name really
 * belongs to us. The default approach is to get the PID of the process
 * that owns it and check it against the original parent PID; that works
 * as long as the tracked process has not forked again and set up D-Bus
 * inside. Alternatively, one may use cgroups to check instead, which
 * works robustly, but only assuming the service being tracked has the
 * cgroup for itself (does not share it) - we can guarantee this under
 * specific service hierarchies, but not generically. Only cgroups v2
 * are supported.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 q66 <q66@chimera-linux.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* if not disabled, assume enabled */
#ifndef HAVE_CGROUPS
#ifdef __linux__
#define HAVE_CGROUPS 1
#else
#define HAVE_CGROUPS 0
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dbus/dbus.h>
#if HAVE_CGROUPS
#include <sys/stat.h>
#include <sys/vfs.h>
#include <mntent.h>
#endif

#define TIMEOUT_SECS 60

#define DBUS_IFACE "org.freedesktop.DBus"
#define DBUS_PATH "/org/freedesktop/DBus"
#define DBUS_SIGNAL "NameOwnerChanged"
#define DBUS_METHOD_GET_PID "GetConnectionUnixProcessID"

struct BusData {
    char const *name;
    int fd;
    uint32_t parent_pid;
    uint32_t pid_serial;
};

#if HAVE_CGROUPS
/* the fs magic is checked once we have a permanent descriptor, to avoid
 * any potential race with something after the mounts check (though unlikely)
 */
#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif
static int cgr_fd = -1;
#endif

static void usage(FILE *f) {
    extern char const *__progname;
    fprintf(f, "Usage: %s [OPTION]... COMMAND [CMD_OPTION]...\n"
"\n"
"Exec COMMAND, wait (with TIMEOUT) for NAME to appear on bus,\n"
"write readiness in FD or in file descriptor referenced by ENV.\n"
"\n"
"If available, the program by default uses system-specific interfaces\n"
"(e.g. cgroups) for tracking forks and ensuring race-free operation.\n"
"This can optionally be overridden.\n"
"\n"
"      -h          Print this message and exit.\n"
"      -e ENV      The environment variable with the file descriptor.\n"
"      -f FD       The file descriptor to write to.\n"
"      -n NAME     The bus name to wait for.\n"
"      -p          Always do an exact PID check.\n"
"      -s          Use the system bus (session bus is default).\n"
"      -t TIMEOUT  How long to wait in seconds (default: %d, 0 to disable).\n",
        __progname, TIMEOUT_SECS
    );
}

static int clockdiff(struct timespec *tp, int *timeout) {
    struct timespec tp2;
    int msdiff;
    if (*timeout < 0) {
        return 1;
    }
    if (!tp->tv_sec && !tp->tv_nsec) {
        clock_gettime(CLOCK_MONOTONIC, tp);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &tp2);
    /* deal with seconds */
    msdiff = tp2.tv_sec - tp->tv_sec;
    msdiff *= 1000;
    /* account for ns */
    msdiff += (tp2.tv_nsec - tp->tv_nsec) / 1000000;
    /* set original time */
    *tp = tp2;
    if (msdiff >= *timeout) {
        return 0;
    }
    *timeout -= msdiff;
    return 1;
}

#if HAVE_CGROUPS
static int cgr_fsopen(void) {
      FILE *mnts = setmntent("/proc/self/mounts", "rb");
      struct mntent *me;
      struct statfs sfs;
      char const *mpath = NULL;
      int fd;
      if (!mnts) {
          /* does not exist, so skip cgroups checks */
          if (errno == ENOENT) {
              return 0;
          }
          return -1;
      }
      while ((me = getmntent(mnts))) {
          if (!strcmp(me->mnt_type, "cgroup2")) {
              mpath = me->mnt_dir;
              break;
          }
      }
      if (!mpath) {
          endmntent(mnts);
          return 0;
      }
      /* now open the filesystem */
      fd = open(mpath, O_DIRECTORY | O_PATH | O_CLOEXEC);
      if ((fd < 0) || fstatfs(fd, &sfs)) {
          endmntent(mnts);
          close(fd);
          return -1;
      }
      if (sfs.f_type != CGROUP2_SUPER_MAGIC) {
          endmntent(mnts);
          close(fd);
          errno = ENOTSUP;
          return -1;
      }
      endmntent(mnts);
      return fd;
}

static int cgr_find(int fsfd, uint32_t pid) {
    FILE *pf;
    char buf[64];
    char *line = NULL;
    ssize_t ret;
    size_t len = 0;
    int cfd = 0;
    snprintf(buf, sizeof(buf), "/proc/%u/cgroup", pid);
    pf = fopen(buf, "rb");
    if (!pf) {
        if (errno == ENOENT) {
            return 0;
        }
        return -1;
    }
    /* locate the v2 cgroup */
    while ((ret = getline(&line, &len, pf)) >= 0) {
        char *nl;
        if (strncmp(line, "0::/", 4)) {
            /* v1 cgroup */
            continue;
        }
        nl = strchr(line, '\n');
        if (nl) {
            *nl = '\0';
        }
        cfd = openat(fsfd, line + 4, O_DIRECTORY | O_PATH | O_CLOEXEC);
        if (cfd < 0) {
            return -1;
        }
        break;
    }
    free(line);
    return cfd;
}

static FILE *cgr_procs_fopen(int fd) {
    FILE *f;
    int pfd = openat(fd, "cgroup.procs", O_RDONLY | O_NOFOLLOW);
    if (pfd < 0) {
        return NULL;
    }
    f = fdopen(pfd, "rb");
    if (!f) {
        int serr = errno;
        close(pfd);
        errno = serr;
        return NULL;
    }
    return f;
}

/* cgroups with processes must be leaf, so no recursion
 *
 * returns 0 if pid is not contained (regardless of number of procs),
 * 1 if only pid is contained, and 2 if pid + other(s) is/are contained
 */
static int cgr_check(FILE *f, uint32_t pid) {
    char buf[32], buf2[32];
    char *ln;
    size_t plen;
    int oth = 0;
    if (!f) {
        return 0;
    }
    snprintf(buf2, sizeof(buf2), "%u", pid);
    plen = strlen(buf2);
    while ((ln = fgets(buf, sizeof(buf), f))) {
        if (strncmp(ln, buf2, plen)) {
            oth = 1;
            continue;
        }
        if (!ln[plen] || (ln[plen] == '\n')) {
            fclose(f);
            return oth + 1;
        }
        oth = 1;
    }
    fclose(f);
    return 0;
}
#endif

static DBusHandlerResult handle_pid_cb(DBusMessage *msg, struct BusData *bd) {
    uint32_t pid;
    /* make sure it matches the method we called, otherwise ignore */
    if (dbus_message_get_reply_serial(msg) != bd->pid_serial) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    /* reset just in case, there should be only one reply matching the serial */
    bd->pid_serial = 0;
    if (!dbus_message_get_args(
        msg,
        NULL,
        DBUS_TYPE_UINT32, &pid,
        DBUS_TYPE_INVALID
    )) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
#if HAVE_CGROUPS
    /* prefer a cgroup check if we can do it; it's less prone to pid reuse
     * (in case of a spurious pid replacement, the new pid would have to
     * belong to the same cgroup, which reduces potential harm)
     */
    if (cgr_fd >= 0) {
        /* check the pid belongs to the same cgroup as the parent */
        FILE *f = cgr_procs_fopen(cgr_fd);
        if (!f) {
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        if (cgr_check(f, pid)) {
            fclose(f);
            goto handle;
        }
        fclose(f);
    } else
#endif
    if (pid == bd->parent_pid) {
        goto handle;
    }
    /* different process claimed it */
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
handle:
    /* ours */
    write(bd->fd, "READY=1\n", sizeof("READY=1"));
    /* we'll quit */
    close(bd->fd);
    bd->fd = -1;
    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult filter_cb(
    DBusConnection *conn, DBusMessage *msg, void *data
) {
    char const *name;
    char const *old_owner;
    char const *new_owner;
    struct BusData *bd = data;
    DBusMessage *nmsg;

    /* do not handle if we've already done that */
    if (bd->fd < 0) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    /* the method is checked inside */
    if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
        return handle_pid_cb(msg, bd);
    }
    /* ignore messages that don't concern us */
    if (!dbus_message_is_signal(msg, DBUS_IFACE, DBUS_SIGNAL)) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    /* if that fails, ignore */
    if (!dbus_message_get_args(
        msg, NULL,
        DBUS_TYPE_STRING, &name,
        DBUS_TYPE_STRING, &old_owner,
        DBUS_TYPE_STRING, &new_owner,
        DBUS_TYPE_INVALID
    )) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    /* if not the one we're tracking, ignore */
    if (strcmp(name, bd->name)) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    /* reset the reply id in case of a subsequent loss */
    bd->pid_serial = 0;
    /* in case of loss, ignore */
    if (!strcmp(new_owner, "")) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    /* getting the pid of the new owner involves a method call; the logic
     * here ensures that if something else gains the name in the meantime,
     * any result received from this will not be used (as the reply serial
     * is reset earlier)
     */
    nmsg = dbus_message_new_method_call(
        DBUS_IFACE,
        DBUS_PATH,
        DBUS_IFACE,
        DBUS_METHOD_GET_PID
    );
    /* could not perform the method call */
    if (!nmsg) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    /* the method takes a string name and returns a uint32_t */
    if (!dbus_message_append_args(
        nmsg,
        DBUS_TYPE_STRING, &new_owner,
        DBUS_TYPE_INVALID
    )) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    /* do the call asynchronously, receive reply later in the mainloop */
    if (!dbus_connection_send(conn, nmsg, NULL)) {
        /* could not send */
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    /* update reply serial; that means we are currently handling the bus
     * name for a specific pid (if we lose it before the response could be
     * received, it will get reset)
     */
    bd->pid_serial = dbus_message_get_serial(nmsg);
    /* we've handled it */
    return DBUS_HANDLER_RESULT_HANDLED;
}

static int get_fd(char const *str) {
    char *end = NULL;
    unsigned long fd;
    if (!str || !*str) {
        return -1;
    }
    fd = strtoul(str, &end, 10);
    if (fd && end && !*end && (fd <= INT_MAX)) {
        int tfd = (int)fd;
        if (!fcntl(tfd, F_GETFD) && (errno != EBADF)) {
            if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
                close(tfd);
                return -1;
            }
            return tfd;
        }
    }
    return -1;
}

int main(int argc, char **argv) {
    DBusBusType bt = DBUS_BUS_SESSION;
    DBusError derr;
    DBusConnection *conn;
    struct BusData bd;
    unsigned long timeout_s = TIMEOUT_SECS;
    int c, timeout;
#if HAVE_CGROUPS
    int do_cgr_check = 1;
#endif
    pid_t p;

    bd.fd = -1;
    bd.name = NULL;
    bd.pid_serial = 0;
    bd.parent_pid = getpid();

    while ((c = getopt(argc, argv, "e:f:hn:pst:")) > 0) {
        switch (c) {
            case 'h':
                usage(stdout);
                return 0;
            case 'e':
                bd.fd = get_fd(getenv(optarg));
                goto err_fd;
            case 'f':
                bd.fd = get_fd(optarg);
err_fd:
                if (bd.fd <= 0) {
                    errx(1, "invalid file descriptor given");
                }
                break;
            case 'n':
                bd.name = optarg;
                if (!*bd.name) {
                    errx(1, "invalid bus name given");
                }
                break;
            case 'p':
#if HAVE_CGROUPS
                do_cgr_check = 0;
#endif
                break;
            case 's':
                bt = DBUS_BUS_SYSTEM;
                break;
            case 't': {
                char *end = NULL;
                timeout_s = strtoul(optarg, &end, 10);
                if (!end || *end || timeout_s > (INT_MAX / 1000)) {
                    errx(1, "invalid timeout given");
                }
                break;
            }
            default:
                warnx("invalid option -- '%c'", c);
                usage(stderr);
                return 1;
        }
    }

    /* convert to milliseconds */
    timeout = timeout_s * 1000;
    if (!timeout) {
        /* for dbus */
        timeout = -1;
    }

    if (bd.fd < 0) {
        errx(1, "no file descriptor given");
    }
    if (!bd.name) {
        errx(1, "no bus name given");
    }

    /* establish as much as we can early on to reduce error handling
     * after fork (and increase robustness of the while thing)
     */

    dbus_error_init(&derr);

    conn = dbus_bus_get(bt, &derr);
    if (!conn) {
        errx(1, "connection error (%s)", derr.message);
    }
    dbus_bus_add_match(
        conn,
        "type='signal',"
        "sender='" DBUS_IFACE "',"
        "interface='" DBUS_IFACE "',"
        "member='" DBUS_SIGNAL "'",
        &derr
    );
    if (dbus_error_is_set(&derr)) {
        errx(1, "failed to register match rule (%s)", derr.message);
    }
    if (!dbus_connection_add_filter(conn, filter_cb, &bd, NULL)) {
        errx(1, "failed to register dbus filter");
    }

#if HAVE_CGROUPS
    /* when tracking cgroups, check what the parent belongs to first */
    if (do_cgr_check) {
        FILE *procs;
        int cfd = -1;
        /* now open the filesystem */
        cgr_fd = cgr_fsopen();
        if (!cgr_fd) {
            goto no_cgr;
        }
        if (cgr_fd < 0) {
            err(1, "could not open cgroup2 filesystem");
        }
        /* ensure the process belongs to a single cgroup */
        cfd = cgr_find(cgr_fd, bd.parent_pid);
        if (!cfd) {
            close(cgr_fd);
            cgr_fd = -1;
            goto no_cgr;
        }
        if (cfd < 0) {
            err(1, "could not obtain cgroup for %u", bd.parent_pid);
        }
        close(cgr_fd);
        cgr_fd = cfd;
        /* cgroup check is only reliable if the parent process is the sole
         * member of the cgroup at the time we start, it means it's likely
         * a service-manager-handled slice and any new processes appearing
         * in it are child processes of the service
         *
         * if there's multiple, it might really be any combo of stuff
         */
        procs = cgr_procs_fopen(cgr_fd);
        if (!procs) {
            err(1, "could not get cgroup processes");
        }
        if (cgr_check(procs, bd.parent_pid) != 1) {
            fclose(procs);
            close(cgr_fd);
            cgr_fd = -1;
        }
        fclose(procs);
    }
no_cgr:
#endif
    p = fork();
    if (p < 0) {
        err(1, "fork failed");
    }
    if (p == 0) {
        struct timespec tp = {0};
        /* child */
        setsid();
        p = fork();
        if (p < 0) {
            err(1, "fork failed");
        }
        if (p) {
            /* the "parent" just exits */
            return 0;
        }
        /* if something resets the fd, it's a signal to exit */
        while ((bd.fd >= 0) && clockdiff(&tp, &timeout)) {
            /* dispatch the dbus connection once */
            if (!dbus_connection_read_write_dispatch(conn, timeout)) {
                break;
            }
        }
        return 0;
    }
    /* original parent; reap forked child first */
    while (waitpid(p, NULL, 0) < 0) {
        if (errno != EINTR) {
            break;
        }
    }
    /* and exec into the intended process */
    execvp(argv[optind], &argv[optind]);
    return 1;
}
