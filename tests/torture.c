/*
 * torture.c - torture library for testing libssh
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2009 by Andreas Schneider <mail@cynapses.org>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
# include <unistd.h>
#endif

#include "torture.h"

static int verbosity = 0;

static int torture_auth_kbdint(ssh_session session,
                               const char *password) {
    const char *prompt;
    char echo;
    int err;

    if (session == NULL || password == NULL) {
        return SSH_AUTH_ERROR;
    }

    err = ssh_userauth_kbdint(session, NULL, NULL);

    prompt = ssh_userauth_kbdint_getprompt(session, 0, &echo);
    if (prompt == NULL) {
        return SSH_AUTH_ERROR;
    }

    if (password && strstr(prompt, "Password:")) {
        if (ssh_userauth_kbdint_setanswer(session, 0, password) < 0) {
            return SSH_AUTH_ERROR;
        }
    }
    err = ssh_userauth_kbdint(session, NULL, NULL);

    return err;
}

int torture_rmdirs(const char *path) {
    DIR *d;
    struct dirent *dp;
    struct stat sb;
    char *fname;

    if ((d = opendir(path)) != NULL) {
        while(stat(path, &sb) == 0) {
            /* if we can remove the directory we're done */
            if (rmdir(path) == 0) {
                break;
            }
            switch (errno) {
                case ENOTEMPTY:
                case EEXIST:
                case EBADF:
                    break; /* continue */
                default:
                    closedir(d);
                    return 0;
            }

            while ((dp = readdir(d)) != NULL) {
                size_t len;
                /* skip '.' and '..' */
                if (dp->d_name[0] == '.' &&
                        (dp->d_name[1] == '\0' ||
                         (dp->d_name[1] == '.' && dp->d_name[2] == '\0'))) {
                    continue;
                }

                len = strlen(path) + strlen(dp->d_name) + 2;
                fname = malloc(len);
                if (fname == NULL) {
                    return -1;
                }
                snprintf(fname, len, "%s/%s", path, dp->d_name);

                /* stat the file */
                if (lstat(fname, &sb) != -1) {
                    if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode)) {
                        if (rmdir(fname) < 0) { /* can't be deleted */
                            if (errno == EACCES) {
                                closedir(d);
                                SAFE_FREE(fname);
                                return -1;
                            }
                            torture_rmdirs(fname);
                        }
                    } else {
                        unlink(fname);
                    }
                } /* lstat */
                SAFE_FREE(fname);
            } /* readdir */

            rewinddir(d);
        }
    } else {
        return -1;
    }

    closedir(d);
    return 0;
}

int torture_isdir(const char *path) {
    struct stat sb;

    if (lstat (path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        return 1;
    }

    return 0;
}

int torture_libssh_verbosity(void){
  return verbosity;
}

ssh_session torture_ssh_session(const char *host,
                                const char *user,
                                const char *password) {
    ssh_session session;

    if (host == NULL) {
        return NULL;
    }

    session = ssh_new();
    if (session == NULL) {
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
        goto failed;
    }

    if (user != NULL) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            goto failed;
        }
    }

    if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity) < 0) {
        goto failed;
    }

    if (ssh_connect(session)) {
        goto failed;
    }

    /* We are in testing mode, so consinder the hostkey as verified ;) */

    if (password != NULL) {
        int err = torture_auth_kbdint(session, password);
        if (err == SSH_AUTH_ERROR) {
            goto failed;
        }
    } else {
        int err = ssh_userauth_autopubkey(session, NULL);
        if (err == SSH_AUTH_ERROR) {
            goto failed;
        }
    }

    return session;
failed:
    if (ssh_is_connected(session)) {
        ssh_disconnect(session);
    }
    ssh_free(session);

    return NULL;
}

int main(int argc, char **argv) {
  struct argument_s arguments;

  arguments.verbose=0;
  torture_cmdline_parse(argc, argv, &arguments);
  verbosity=arguments.verbose;

  return torture_run_tests();
}

/* vim: set ts=4 sw=4 et cindent syntax=c.doxygen: */
