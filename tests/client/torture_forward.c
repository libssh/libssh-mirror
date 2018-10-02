/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013 by Andreas Schneider <asn@cryptomilk.org>
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

#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/libssh.h>

#include <errno.h>
#include <sys/types.h>
#include <pwd.h>

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state);

    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static void setup(void **state)
{
    ssh_session session;
    struct passwd *pwd;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    session = torture_ssh_session(TORTURE_SSH_SERVER,
                                  NULL,
                                  TORTURE_SSH_USER_ALICE,
                                  NULL);

    assert_non_null(session);

    *state = session;
}

static void teardown(void **state)
{
    ssh_session session = (ssh_session) *state;

    assert_non_null(session);

    if (ssh_is_connected(session)) {
            ssh_disconnect(session);
    }
    ssh_free(session);
}

static void torture_ssh_forward(void **state)
{
    ssh_session session = (ssh_session) *state;
    ssh_channel c;
    int dport;
    int bound_port;
    int rc;

    rc = ssh_channel_listen_forward(session, "127.0.0.21", 8080, &bound_port);
    assert_int_equal(rc, SSH_OK);

    c = ssh_channel_accept_forward(session, 10, &dport);
    /* We do not get a listener and run into the timeout here */
    assert_null(c);

    ssh_channel_send_eof(c);
    ssh_channel_close(c);
}

int torture_run_tests(void) {
    int rc;
    struct torture_state *s = NULL;

    UnitTest tests[] = {
        unit_test_setup_teardown(torture_ssh_forward, setup, teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    sshd_setup((void **)&s);
    rc = run_tests(tests);
    sshd_teardown((void **)&s);

    ssh_finalize();
    return rc;
}
